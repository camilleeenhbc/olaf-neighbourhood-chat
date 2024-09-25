import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # for AES
from cryptography.hazmat.primitives import hashes


class Message:
    def __init__(self, content, message_type="chat", destination_servers=None):
        # assign the attributes
        self.content = content
        self.encrypted_content = None
        self.participants = []
        self.iv = None  # base64 encoded AES initialisation vector
        self.symm_keys = []
        self.counter = 0  # the nonce
        self.message_type = message_type

    # Function to encrypt the AES key
    def encrypt_key(self, receiver_public_key, aes_key):
        encrypted_key = receiver_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(encrypted_key).decode()

    # Decrypt the AES key
    def decrypt_key(self, aesKey):
        return self.private_key.decrypt(
            aesKey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # Encrypt message with AES key
    # Perform AES in GCM mode
    # Key length of 32 bytes (128 bits)
    def encrypt_with_aes(self, receiver_public_key):
        # IV should be 16  bytes (randomly generated)
        self.iv = os.urandom(16)
        aes_key = os.urandom(32)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(self.iv))
        encryptor = cipher.encryptor()
        self.encrypted_content = (
            encryptor.update(self.content.encode()) + encryptor.finalize()
        )

        # encrypt AES key with RSA
        encryptedAES = self.encrypt_key(receiver_public_key, aes_key)

        # Encode key with base64
        self.symm_keys.append(encryptedAES)

    # Decrypt message with AES key
    def decrypt_with_aes(self, key: bytes):
        cipher = Cipher(algorithms.AES(key), modes.GCM(self.iv))
        decryptor = cipher.decryptor()
        decrypted_content = (
            decryptor.update(self.encrypted_content.encode()) + decryptor.finalize()
        )
        return decrypted_content.decode()

    def prepare_chat_message(self, recipient_public_keys, destination_servers):
        """Prepare an encrypted chat message, including AES key encryption."""

        # Encrypt the message and generate keys
        self.encrypt_with_aes(recipient_public_keys)

        # Build the chat message structure
        chat_message = {
            "data": {
                "type": self.message_type,
                "destination_servers": destination_servers,  # Addresses of destination servers
                "iv": base64.b64encode(self.iv).decode(),  # Base64 encoded IV
                "symm_keys": self.symm_keys,  # Encrypted AES keys for recipients
                "chat": base64.b64encode(
                    self.encrypted_content
                ).decode(),  # Base64 encoded AES-encrypted content
            }
        }

        return json.dumps(chat_message, indent=2)
