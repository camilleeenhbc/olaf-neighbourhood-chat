import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class Message:
    def __init__(self, content, messageType="chat",destinationServers=None):
        # assign the attributes
        self.content = content
        self.encryptedContent = None
        self.participants = []
        self.iv = None #base64 encoded AES initialisation vector
        self.symmKeys = []
        self.signature = None
        self.counter = 0    #the nonce
        self.messageType=messageType
        self.destinationServers = destinationServers if destinationServers else []
    
    # #Function to encrypt message with receiver's public key with OAEP padding
    # def encryptWithRSA(self, receiverPublicKey):
    #     self.encryptedContent = receiverPublicKey.encrypt(
    #         self.content.encode(), #convert string
    #         #Apply OAEP padding
    #         padding.OAEP(
    #             #SHA-256 digest/hash function used
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     )
        
        
    # def decrypt_with_rsa(self, privateKey):
    #     self.encryptedContent = base64.b64decode(self.encryptedContent) 
        
    #     decrypted_content = privateKey.decrypt(
    #         self.encryptedContent,
    #         padding.OAEP(
    #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #             algorithm=hashes.SHA256(),
    #             label=None
    #         )
    #     )
    #     self.content = decrypted_content.decode('utf-8') 

    def formatChat(self):
        chat={
            "type": "signed_data",
            "data": 
                { 
                    "type":self.messageType,
                    "destination_servers": self.destinationServers,  #address of destination sevrer
                    "iv": base64.b64encode(self.iv).decode(),   #base64 encoded IV
                    "symm_keys":self.symmKeys,
                    #Base64 encoded AES encrypted 
                    "chat":base64.b64encode(self.encryptedContent).decode()
                },
            "counter": self.counter,
            "signature": self.signature
        }
        return json.dumps(chat,indent=2)

    
    