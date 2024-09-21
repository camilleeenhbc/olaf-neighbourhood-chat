import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  #for AES
from cryptography.hazmat.primitives import hashes

class Client:
    def __init__(self):
        self.counter=0
        self.privateKey=rsa.generatePrivateKey(
            public_exponent=65537,    
            key_size=2048,   #modulus length
            backend=default_backend()
        )
        self.publicKey = self.privateKey.publicKey()
        self.fingerprint = self.generateFingerprint(self.publicKey)
        
        
    #Perform AES in GCM mode
    #Key length of 32 bytes (128 bits)
    def encryptWithAES(self, key):
        #IV should be 16 bytes (randomly generated)
        iv=os.urandom(16)
        
        cipher = Cipher(algorithms.AES(key),modes.GCM(iv))
        encryptor=cipher.encryptor()
        self.encryptedContent=encryptor.update(self.content.encode())+encryptor.finalize()
        #Encode key with base64
        self.symmKeys.append(base64.b64encode(key).decode())
    
    #Sign the message using the RSA-PSS scheme
    #Signature should be Base64 of data + counter
    def signMessage(self, privateKey):
        message=self.content+str(self.counter).encode()
        signature=privateKey.sign(
        message,padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
        )
        self.signature = base64.b64.encode(signature).decode()
    
    def verifySignature(self,publicKey):
        try:
            publicKey.verify(
                base64.b64decode(self.signature),(self.content + str(self.counter)).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
            

    def decrypt_with_aes(self, key: bytes):
        #IV should be 16 bytes (randomly generated)
        iv=os.urandom(16)
        cipher = Cipher(algorithms.AES(key),modes.GCM(iv))
        decryptor=cipher.decryptor()
        self.content=decryptor.update(self.content.encode())+decryptor.finalize()
        print(self.content)
