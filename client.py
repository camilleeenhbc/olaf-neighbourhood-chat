import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class Client:
    def __init__(self):
        self.counter = 0
        self.privateKey = rsa.generatePrivateKey(
            public_exponent=65537,
            key_size=2048,  # modulus length
            backend=default_backend(),
        )
        self.publicKey = self.privateKey.publicKey()
        self.fingerprint = self.generateFingerprint(self.publicKey)

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
