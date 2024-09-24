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
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from message import Message

logging.basicConfig(level=logging.INFO)


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

    def generate_fingerprint(self, public_key):
        """Generates a fingerprint based on the public key (hash)."""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_bytes).hexdigest()

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
        self.signature = base64.b64.encode(signature).decode()
        return self.signature

    def verify_signature(self, public_key):
        try:
            public_key.verify(
                base64.b64decode(self.signature),
                (self.content + str(self.counter)).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256), salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    # CONNECT TO SERVER
    async def connect_to_server(self):
        try:
            async with connect(f"ws://{self.server_url}") as websocket:
                logging.info(f"Connected to {self.server_url}")
                await self.send_hello(websocket)
                await self.listen(websocket)
        except Exception as e:
            logging.error(f"Failed to connect to {self.server_url}: {e}")

    async def listen(self, websocket):
        """Listen for incoming messages"""
        try:
            async for message in websocket:
                logging.info(f"Received message from server: {message}")
                data = json.loads(message)
                self.handle_message(data)
        except Exception as e:
            logging.error(f"Error in receiving message: {e}")

    # SEND MESSAGES
    async def send_hello(self, websocket):
        """Send the hello message with public key"""
        hello_message = {"data": {"type": "hello", "public_key": self.fingerprint}}
        await websocket.send(json.dumps(hello_message))
        logging.info(f"Sent hello message to {self.server_url}")

    async def send_chat(
        self, websocket, message_content, destination_servers, recipient_public_keys
    ):
        """Send an encrypted chat message."""
        # Prepare the encrypted chat message with the Message class
        message = Message(message_content)
        for public_key in recipient_public_keys:
            print(type(public_key))



        # Prepare the chat message (encrypt it and structure it properly)
        chat_data = message.prepare_chat_message(
            recipient_public_keys, destination_servers
        )

        signed_chat_message = {
            "type": "signed_data",
            "data": chat_data,
            "counter": self.counter,
            "signature": self.sign_message(chat_data),
        }

        await websocket.send(json.dumps(signed_chat_message))
        logging.info("Sent encrypted chat message")

    def handle_message(self, data):
        """Handle incoming messages."""
        logging.info(f"Handling message: {data}")

