import json
import websockets
import asyncio
import logging
import src.utils.crypto as crypto
import aiohttp
import base64

from typing import List, Optional, Union, Dict
from websockets import connect
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from src.utils.message import Message


class Client:
    def __init__(self, server_url):
        self.counter = 0
        self.hostname = server_url.split(":")[0]
        self.port = int(server_url.split(":")[1])
        self.server_url = server_url

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # modulus length
            backend=default_backend(),
        )
        self.public_key = crypto.load_pem_public_key(
            crypto.export_public_key(self.private_key.public_key())
        )

        self.fingerprint = crypto.generate_fingerprint(self.public_key)
        self.websocket = None

        # List of currently online users
        # { server_address1: [{public_key, fingerprint}, {public_key, fingerprint}] }
        self.online_users: Dict[str, List[Dict]] = {}

        self.client_list_event = asyncio.Event()

    def get_public_key_from_fingerprint(
        self, fingerprint: str
    ) -> Union[str, Optional[rsa.RSAPublicKey]]:
        """
        Retrieve a public key using the sender's fingerprint from the online users list.
        """
        for server, clients in self.online_users.items():
            for client in clients:
                client_fingerprint = client["fingerprint"]
                if client_fingerprint == fingerprint:
                    return (server, client["public_key"])
        return (None, None)

    def get_public_keys_from_fingerprints(
        self, fingerprints: List[str]
    ) -> List[Union[str, rsa.RSAPublicKey]]:
        """
        Retrieve a public key using the sender's fingerprint from the online users list.
        """
        public_keys = [None] * len(fingerprints)
        if self.fingerprint in fingerprints:
            public_keys[fingerprints.index(self.fingerprint)] = (
                self.server_url,
                self.public_key,
            )

        for server, clients in self.online_users.items():
            for client in clients:
                client_fingerprint = client["fingerprint"]
                if client_fingerprint in fingerprints:
                    public_keys[fingerprints.index(client_fingerprint)] = (
                        server,
                        client["public_key"],
                    )

        if None in public_keys:
            return []

        return public_keys

    def sign_message(self, message: str):
        self.signature = crypto.sign_message(message, self.counter, self.private_key)
        return self.signature

    # CONNECT TO SERVER
    async def connect_to_server(self):
        """Create connection to server"""
        try:
            self.websocket = await connect(f"ws://{self.hostname}:{self.port}")
            logging.info(f"Connected to {self.hostname}:{self.port}")
            await self.send_message(self.websocket, chat_type="hello")
            listen_thread = asyncio.create_task(self.listen(self.websocket))
            await self.request_client_list()  # fetch online users
            await listen_thread
        except websockets.ConnectionClosed:
            logging.info("Disconnected")
            await self.disconnect()
        except Exception as e:
            logging.error(f"Failed to connect to {self.hostname}:{self.port}: {e}")
        finally:
            await self.disconnect()

    async def disconnect(self):
        """Disconnect client from server"""
        if self.websocket:
            logging.info("Disconnecting")
            await self.websocket.close()

    async def listen(self, websocket):
        """Listen for incoming messages"""
        try:
            async for message in websocket:
                data = json.loads(message)
                asyncio.create_task(self.receive_message(data))
        except Exception as e:
            logging.error(f"Error in receiving message: {e}")

    # SEND MESSAGE
    async def send_message(
        self,
        websocket,
        message_content="",
        chat_type="chat",
        destination_servers=[],
        recipient_public_keys: List[rsa.RSAPublicKey] = [],
        participants=[],
    ):
        """
        Send different types of messages
        """

        if chat_type == "hello":
            message_data = {
                "type": "hello",
                "public_key": crypto.export_public_key(
                    self.public_key
                ),  # Exporting public key as PEM format
            }

        elif chat_type == "chat":  # Private chat
            message = Message(message_content)
            message_data = message.prepare_chat_message(
                recipient_public_keys=recipient_public_keys,
                destination_servers=destination_servers,
                participants=participants,
            )

        elif chat_type == "public_chat":  # Public chat
            message_data = {
                "type": "public_chat",
                "sender": self.fingerprint,
                "message": message_content,
            }

        else:
            logging.error("Invalid chat type specified.")
            return

        # Inrement counter
        self.counter += 1

        signed_message = {
            "type": "signed_data",
            "data": message_data,
            "counter": self.counter,
            "signature": self.sign_message(json.dumps(message_data)),
        }

        await websocket.send(json.dumps(signed_message))
        # print(signed_message)
        logging.info(f"Sent {chat_type} message.")

    async def request_client_list(self):
        self.client_list_event.clear()
        request = {
            "type": "client_list_request",
        }

        await self.websocket.send(json.dumps(request))
        await self.client_list_event.wait()

    # HANDLE INCOMING MESSAGES
    async def receive_message(self, data):
        """Handle incoming messages from other servers and clients."""
        message_type = data.get("type", None)

        if message_type == "client_list":
            self.handle_client_list(data)
        elif message_type == "signed_data":
            await self.handle_signed_data(data)
        else:
            logging.error(f"Invalid message: {data}")

    def handle_client_list(self, data):
        servers = data.get("servers", None)
        if servers is None:
            logging.error("Invalid client_list format")
            return

        for item in servers:
            server_address, clients = item["address"], item["clients"]

            # Transform public key string to public key object
            self.online_users[server_address] = []
            for i, public_key in enumerate(clients):
                public_key = crypto.load_pem_public_key(public_key)
                self.online_users[server_address].append(
                    {
                        "public_key": public_key,
                        "fingerprint": crypto.generate_fingerprint(public_key),
                    }
                )

        self.client_list_event.set()

    async def handle_signed_data(self, data):
        """Handle and verify signed_data messages"""
        message_data = data.get("data", {})
        signature = data.get("signature", "")
        counter = data.get("counter", 0)

        message_type = message_data.get("type", None)
        if message_type == "public_chat":
            await self.handle_public_chat(signature, message_data, counter)
        elif message_type == "chat":
            await self.handle_chat(signature, message_data, counter)
        else:
            logging.error("Invalid message type")

    def check_permissions(self, message):
        if isinstance(message, str) and "admin" == message:
            return True
        return False

    async def handle_public_chat(self, signature: str, message: dict, counter):
        """
        Handles incoming public chat messages and verifies the sender's signature.
        """
        try:
            await self.request_client_list()  # Fetch online users

            sender_fingerprint = message.get("sender")
            public_message = message.get("message", "")
            permission = self.check_permissions(public_message)

            # Get public keys from online users
            sender_server_address, sender_public_key = (
                self.get_public_key_from_fingerprint(sender_fingerprint)
            )
            if permission:
                output = f"(Public chat) ({sender_server_address})\n"
                output += f"  From {sender_fingerprint}:\n"
                output += f"    {public_message}\n"
                print(output)
                return
            else:
                if sender_public_key is None:
                    logging.error("Cannot get public key from public chat sender")
                    return

                if crypto.verify_signature(
                    sender_public_key, signature, json.dumps(public_message), counter
                ):
                    logging.error(
                        f"Signature verification failed for sender: {sender_fingerprint}"
                    )
                    return

                output = f"(Public chat) ({sender_server_address})\n"
                output += f"  From {sender_fingerprint}:\n"
                output += f"    {public_message}\n"
                print(output)
        except Exception as e:
            logging.error(f"Error processing public chat message: {e}")

    async def handle_chat(self, signature: str, message: dict, counter):
        """
        Handles incoming chat messages, verifies the sender's signature,
        and logs the message if the signature is valid.
        """
        try:
            await self.request_client_list()  # Fetch online users

            encrypted_chat: dict = message.get("chat", {})
            iv = base64.b64decode(message.get("iv", ""))
            symm_keys = message.get("symm_keys", [])

            # Try decrypting chat message
            chat = None
            for symm_key in symm_keys:
                chat = Message(encrypted_chat).decrypt_with_aes(
                    self.private_key, symm_key, iv
                )
                if chat is not None:
                    break

            # If chat cannot be encrypted, ignore because the message isn't for this client
            if chat is None:
                return

            chat = json.loads(chat)
            participants: list = chat.get("participants", [])

            # Get sender's public key from fingerprint
            public_keys = self.get_public_keys_from_fingerprints(participants)
            if len(public_keys) == 0:
                logging.error("Cannot get public keys for every participants")
                return

            sender_server_address, sender_public_key = public_keys[0]
            if sender_public_key is None:
                logging.error("Cannot get public key from chat sender")
                return

            if crypto.verify_signature(
                sender_public_key, signature, json.dumps(message), counter
            ):
                logging.error("Signature verification failed for sender")
                return

            output = f"(Chat) ({', '.join(participants)})\n"
            output += f"  From ({sender_server_address}) {participants[0]}:\n"
            output += f"    {chat.get('message', '')}\n"
            print(output)

        except Exception as e:
            logging.error(f"Error processing chat message: {e}")

    async def upload_file(self, filename):
        """Upload a file to the server using an HTTP POST request"""
        url = f"http://{self.hostname}:{str(self.port+1000)}/api/upload"
        async with aiohttp.ClientSession() as session:
            with open(filename, "rb") as f:
                files = {"file": f}
                # POST request
                async with session.post(url, data=files) as response:
                    if response.status == 200:
                        json_response = await response.json()
                        logging.info("File uploaded successfully.")
                        return json_response["response"]["body"]["file_url"]
                    elif response.status == 413:
                        logging.error(
                            "File too large. Server returned 413 Payload Too Large."
                        )
                    else:
                        logging.error(
                            f"Failed to upload file. Status code: {response.status}"
                        )
                        logging.error(await response.text())

            return None

    async def download_file(self, url):
        """Download a file from the aiohttp server using the unique ID."""
        try:
            # Create a new aiohttp session
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        # Retrieve the filename from the headers
                        content_disposition = response.headers.get(
                            "Content-Disposition"
                        )
                        original_filename = content_disposition.split('filename="')[1][
                            :-1
                        ]

                        # Save the file with its original filename
                        with open(original_filename, "wb") as f:
                            while True:
                                chunk = await response.content.read(1024)
                                if not chunk:
                                    break
                                f.write(chunk)

                        logging.info(
                            f"File {original_filename} downloaded successfully."
                        )
                    else:
                        logging.error(
                            f"Failed to download file: {response.status} {await response.text()}"
                        )
        except aiohttp.ClientError as e:
            logging.error(f"Error downloading file: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during file download: {e}")
