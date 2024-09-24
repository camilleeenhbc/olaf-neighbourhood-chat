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

logging.basicConfig(level=logging.INFO)


class Client:
    def __init__(self, server_url):
        self.counter = 0
        self.server_url = server_url
        self.privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # modulus length
            backend=default_backend(),
        )
        self.publicKey = self.privateKey.public_key()
        self.fingerprint = self.generate_fingerprint(self.publicKey)

    def generate_fingerprint(self, public_key):
        """Generates a fingerprint based on the public key (hash)."""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_bytes).hexdigest()

    async def connect_to_server(self):
        try:
            async with connect(f"ws://{self.server_url}") as websocket:
                logging.info(f"Connected to {self.server_url}")
                await self.send_hello(websocket)
                await self.listen(websocket)
        except Exception as e:
            logging.error(f"Failed to connect to {self.server_url}: {e}")

    async def send_hello(self, websocket):
        """Send the hello message with public key"""
        hello_message = {"data": {"type": "hello", "public_key": self.fingerprint}}
        await websocket.send(json.dumps(hello_message))
        logging.info(f"Sent hello message to {self.server_url}")

    async def listen(self, websocket):
        """Listen for incoming messages"""
        try:
            async for message in websocket:
                logging.info(f"Received message from server: {message}")
                data = json.loads(message)
                self.handle_message(data)
        except Exception as e:
            logging.error(f"Error in receiving message: {e}")

    # Function to encrypt the AES key
    def encrypt(self, receiverPublicKey, aesKey):
        return receiverPublicKey.encrypt(
            aesKey,
            # Apply OAEP padding
            padding.OAEP(
                # SHA-256 digest/hash function used
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # Decrypt the AES key
    def decrypt(self, aesKey):
        return self.private_key.decrypt(
            aesKey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # Sign the message using the RSA-PSS scheme
    # Signature should be Base64 of data + counter
    def signMessage(self, message):
        signature = self.privateKey.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        self.signature = base64.b64.encode(signature).decode()
        return self.signature

    def verifySignature(self, publicKey):
        try:
            publicKey.verify(
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


# Running the client
async def run_client():
    client = Client("localhost:80")
    await client.connect_to_server()


if __name__ == "__main__":
    asyncio.run(run_client())
