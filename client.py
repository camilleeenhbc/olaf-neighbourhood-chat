import json
import base64
import os
import websockets
import asyncio
import logging
import hashlib
from websockets import connect
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from message import Message
import crypto
import aiohttp

logging.basicConfig(format="%(levelname)s:\t%(message)s", level=logging.INFO)


class Client:
    def __init__(self, server_url):
        self.counter = 0
        self.server_url = server_url
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # modulus length
            backend=default_backend(),
        )
        self.public_key = self.private_key.public_key()
        self.fingerprint = crypto.generate_fingerprint(self.public_key)
        self.websocket = None

        # List of currently online users { server_address1: [client public key 1, client public key 2, ...] }
        self.online_users = {}

    async def get_public_key_from_fingerprint(self, fingerprint):
        """
        Retrieve a public key using the sender's fingerprint from the online users list.
        """
        await self.request_client_list()  # Fetch online users
        for server, clients in self.online_users.items():
            for client in clients:
                # Assuming the client entry contains the public key in PEM format
                public_key_pem = client
                public_key = crypto.load_pem_public_key(public_key_pem)
                client_fingerprint = crypto.generate_fingerprint(public_key)
                if client_fingerprint == fingerprint:
                    return public_key
        return None

    # SIGNATURE
    # Sign the message using the RSA-PSS scheme
    # Signature should be Base64 of data + counter
    def sign_message(self, message):
        message_bytes = message + str(self.counter).encode()
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        self.signature = base64.b64encode(signature).decode()
        return self.signature

    def verify_signature(self, public_key, signature, message_data, counter):
        try:
            # Verify signature using sender's public key and the original message data
            message_bytes = message_data.encode() + str(counter).encode()
            public_key.verify(
                base64.b64decode(signature),
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            logging.error("Invalid signature.")
            return False

    # CONNECT TO SERVER
    async def connect_to_server(self):
        """Create connection to server"""
        try:
            self.websocket = await connect(f"ws://{self.server_url}")
            logging.info(f"Connected to {self.server_url}")
            await self.send_message(self.websocket, chat_type="hello")
            await self.request_client_list()  # fetch online users
            await self.listen(self.websocket)
        except websockets.ConnectionClosed:
            logging.info("Disconnected")
        except Exception as e:
            logging.error(f"Failed to connect to {self.server_url}: {e}")

    async def disconnect(self):
        """Disconnect client from server"""
        logging.info("Disconnecting")
        await self.websocket.close()

    async def listen(self, websocket):
        """Listen for incoming messages"""
        try:
            async for message in websocket:
                # logging.info(f"Received message from server: {message}")
                data = json.loads(message)
                await self.receive_message(data)
        except Exception as e:
            logging.error(f"Error in receiving message: {e}")

    # SEND MESSAGE
    async def send_message(
        self,
        websocket,
        message_content="",
        chat_type="chat",
        destination_servers=[],
        recipient_public_keys=[],
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
        # Sign message
        chat_message_bytes = json.dumps(message_data).encode()

        signed_message = {
            "type": "signed_data",
            "data": message_data,
            "counter": self.counter,
            "signature": self.sign_message(chat_message_bytes),
        }

        await websocket.send(json.dumps(signed_message))
        # print(signed_message)
        logging.info(f"Sent {chat_type} message.")

    async def request_client_list(self):
        request = {
            "type": "client_list_request",
        }

        await self.websocket.send(json.dumps(request))

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
        logging.info("Client receives client_list")

        servers = data.get("servers", None)
        # print(servers)
        if servers is None:
            logging.error("Invalid client_list format")
            return

        log = "List of online users:\n"

        for item in servers:
            server_address, clients = item["address"], item["clients"]

            # Transform public key string to public key object
            client_public_keys = []
            for client in clients:
                client_public_keys.append(crypto.load_pem_public_key(client))

            self.online_users[server_address] = client_public_keys
            for i in range(len(clients)):
                log += f"- {i}@{server_address}\n"

        logging.info(log)

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

    def get_username_from_public_key(self, public_key):
        """Get username from public key in the format of index@server_address"""
        for server_address, clients in self.online_users.items():
            if public_key in clients:
                index = clients.index(public_key)
                return f"{index}@{server_address}"
        return None

    def get_public_key_from_username(self, username: str):
        """Get public key from username in the format of index@server_address"""
        index, address = username.split("@")
        index = int(index)
        try:
            return self.online_users[address][index]
        except:
            return None

    async def handle_public_chat(self, signature, message, counter):
        """
        Handles incoming public chat messages and verifies the sender's signature.
        """
        try:
            sender = message.get("sender")
            # Get public keys from online users
            sender_public_key = await self.get_public_key_from_fingerprint(sender)
            if sender_public_key is None:
                logging.error(f"Cannot get public key from public chat sender")
                return

            if self.verify_signature(
                sender_public_key, signature, json.dumps(message), counter
            ):
                public_message = message.get("message", "")
                sender_username = self.get_username_from_public_key(sender_public_key)
                logging.info(f"(public chat) {sender_username}: {public_message}")
                # logging.info(f"Received public chat from {sender}: {public_message}")
            else:
                logging.error(f"Signature verification failed for sender: {sender}")
        except Exception as e:
            logging.error(f"Error processing public chat message: {e}")

    async def handle_chat(self, signature, message, counter):
        """
        Handles incoming chat messages, verifies the sender's signature,
        and logs the message if the signature is valid.
        """
        try:
            chat = message.get("chat", {})
            participants = chat.get("participants", [])
            sender = participants[0]  # sender's fingerprint comes first
            sender_public_key = await self.get_public_key_from_fingerprint(sender)

            if self.verify_signature(
                sender_public_key, signature, json.dumps(message), counter
            ):
                public_message = chat.get("message", "")
                logging.info(f"Received chat message: {public_message}")
            else:
                logging.error(f"Signature verification failed for sender: {sender}")
        except Exception as e:
            logging.error(f"Error processing chat message: {e}")

    async def upload_file(self, filename):
        """Upload a file to the server using an HTTP POST request"""
        logging.info(f"Uploading file {filename}")
        url = f"http://localhost:1000/upload"
        try:
            async with aiohttp.ClientSession() as session:
                with open(filename, "rb") as f:
                    files = {"file": f}
                    logging.info(f"Uploading file {filename}")

                    # POST request
                    async with session.post(url, data=files) as response:
                        if response.status == 200:
                            logging.info(f"File {filename} uploaded successfully.")
                        else:
                            logging.error(
                                f"Failed to upload file {filename}. Status: {response.status}"
                            )
        except aiohttp.ClientError as e:
            logging.error(f"Error during file upload: {e}")
        except KeyboardInterrupt:
            logging.warning("Upload interrupted by user.")
        finally:
            logging.info("Upload process cleaned up.")

    async def download_file(self, filename):
        """Download a file from the aiohttp server asynchronously."""
        url = f"http://localhost:1000/download/{filename}"

        try:
            # Create a new aiohttp session
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        # Write the response content to a file
                        with open(filename, "wb") as f:
                            while True:
                                chunk = await response.content.read(1024)
                                if not chunk:
                                    break
                                f.write(chunk)

                        logging.info(f"File {filename} downloaded successfully.")
                    else:
                        logging.error(
                            f"Failed to download file: {response.status} {await response.text()}"
                        )
        except aiohttp.ClientError as e:
            logging.error(f"Error downloading file: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during file download: {e}")
