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
        self.fingerprint = self.generate_fingerprint(self.public_key)
        self.websocket = None

        # List of currently online users { server_address1: [client public key 1, client public key 2, ...] }
        self.online_users = {}

    def generate_fingerprint(self, public_key):
        """Generates a fingerprint based on the public key (hash)."""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_bytes).hexdigest()
    

    def get_public_key_from_fingerprint(self, fingerprint):
        """
        Retrieve a public key using the sender's fingerprint from the online users list.
        """
        self.request_client_list() # Fetch online users
        for server, clients in self.online_users.items():
            for client in clients:
                print(client)
                # Assuming the client entry contains the public key in PEM format
                public_key_pem = client
                public_key = serialization.load_pem_public_key(
                    public_key_pem.encode(), backend=default_backend()
                )
                client_fingerprint = self.generate_fingerprint(public_key)
                if client_fingerprint == fingerprint:
                    return public_key
        return None

    def export_public_key(self):
        """Export the public key to PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # SIGNATURE
    # Sign the message using the RSA-PSS scheme
    # Signature should be Base64 of data + counter
    def sign_message(self, message):
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        self.signature = base64.b64encode(signature).decode()
        return self.signature

    def verify_signature(self, public_key, signature, message_data):
        try:
            # Verify signature using sender's public key and the original message data
            public_key.verify(
                base64.b64decode(signature),  
                message_data.encode(), 
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logging.error("Invalid signature.")
            return False

    # CONNECT TO SERVER
    async def connect_to_server(self):
        """ Create connection to server """
        try:
            self.websocket = await connect(f"ws://{self.server_url}")
            logging.info(f"Connected to {self.server_url}")
            await self.send_message(self.websocket, chat_type="hello")
            await self.request_client_list() # fetch online users
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
                "public_key": self.export_public_key().decode(),  # Exporting public key as PEM format
            }

        elif chat_type == "chat":  # Private chat
            message = Message(message_content)
            message_data = message.prepare_chat_message(
                chat_type="chat",
                recipient_public_keys=recipient_public_keys,
                destination_servers=destination_servers,
            )

        elif chat_type == "group_chat":  # Group chat
            message = Message(message_content)
            message_data = message.prepare_chat_message(
                chat_type="group_chat",
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

    async def receive_message(self, data):
        """Handle incoming messages."""
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
            self.online_users[server_address] = clients
            for i in range(len(clients)):
                log += f"- {i}@{server_address}\n"

        logging.info(log)
        
    async def handle_signed_data(self, data):
        """Handle and verify signed messages"""
        message_data = data.get("data", {})
        signature = data.get("signature", "")
        counter = data.get("counter", 0)

        message_type = message_data.get("type", None)
        
        if message_type == "public_chat":
            sender_fingerprint = message_data.get("sender")
            # Get public keys from online users
            sender_public_key = self.get_public_key_from_fingerprint(sender_fingerprint)
            self.verify_signature(sender_public_key, signature, json.dumps(message_data))
            await self.handle_public_chat(message_data)
        

    async def handle_public_chat(self, message):
        sender = message.get("sender", "Unknown")
        public_message = message.get("message", "")
        logging.info(f"Received public chat from {sender}: {public_message}")