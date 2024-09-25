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

        if chat_type == "hello":
            chat_message = {
                "data": {
                    "type": "hello",
                    "public_key": self.export_public_key().decode(),  # Exporting public key as PEM format
                }
            }

        elif chat_type == "chat":  # Private chat
            message = Message(message_content)
            chat_message = message.prepare_chat_message(
                chat_type="chat",
                recipient_public_keys=recipient_public_keys,
                destination_servers=destination_servers,
            )

        elif chat_type == "group_chat":  # Group chat
            message = Message(message_content)
            chat_message = message.prepare_chat_message(
                chat_type="group_chat",
                recipient_public_keys=recipient_public_keys,
                destination_servers=destination_servers,
                participants=participants,
            )

        elif chat_type == "public_chat":  # Public chat
            chat_message = {
                "data": {
                    "type": "public_chat",
                    "sender": self.fingerprint,
                    "message": message_content,
                }
            }

        else:
            logging.error("Invalid chat type specified.")
            return

        # Sign message except for public chat
        # if chat_type != "public_chat":
        chat_message_bytes = json.dumps(chat_message).encode()
        signed_message = {
            "type": "signed_data",
            "data": chat_message,
            "counter": self.counter,
            "signature": self.sign_message(chat_message_bytes),
        }
        await websocket.send(json.dumps(signed_message))
        # print(signed_message)
        logging.info(f"Sent {chat_type} message.")

    def handle_message(self, data):
        """Handle incoming messages."""
        logging.info(f"Handling message: {data}")
