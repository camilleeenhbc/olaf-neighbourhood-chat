import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # for AES
from cryptography.hazmat.primitives import hashes


class Message:
    def __init__(self, content, messageType="chat", destinationServers=None):
        # assign the attributes
        self.content = content
        self.encryptedContent = None
        self.participants = []
        self.iv = None  # base64 encoded AES initialisation vector
        self.symmKeys = []
        self.signature = None
        self.counter = 0  # the nonce
        self.messageType = messageType
        self.destinationServers = destinationServers if destinationServers else []


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
    
    
    # Perform AES in GCM mode
    # Key length of 32 bytes (128 bits)
    def encryptWithAES(self, key, receiverPublicKey):
        # IV should be 16 bytes (randomly generated)
        self.iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.GCM(self.iv))
        encryptor = cipher.encryptor()
        self.encryptedContent = (
            encryptor.update(self.content.encode()) + encryptor.finalize()
        )
        
        #encrypt AES key with RSA
        encryptedAES = self.encrypt(receiverPublicKey,key )
        
        # Encode key with base64
        self.symmKeys.append(base64.b64encode(encryptedAES).decode())
        
    def decrypt_with_aes(self, key: bytes):
        cipher = Cipher(algorithms.AES(key), modes.GCM(self.iv))
        decryptor = cipher.decryptor()
        decryptedContent = (
            decryptor.update(self.encryptedContent.encode()) + decryptor.finalize()
        )
        return decryptedContent.decode()
    
    def sign(self, client):
        message = self.content.encode() + str(self.counter).encode()
        self.signature = client.signMessage(message)

    def formatChat(self):
        chat = {
            "type": "signed_data",
            "data": {
                "type": self.messageType,
                "destination_servers": self.destinationServers,  # address of destination sevrer
                "iv": base64.b64encode(self.iv).decode(),  # base64 encoded IV
                "symm_keys": self.symmKeys,
                # Base64 encoded AES encrypted
                "chat": base64.b64encode(self.encryptedContent).decode(),
            },
            "counter": self.counter,
            "signature": self.signature,
        }
        return json.dumps(chat, indent=2)
