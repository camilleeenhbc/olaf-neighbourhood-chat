import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_fingerprint(public_key: rsa.RSAPublicKey):
    """Generates a fingerprint based on the public key (hash)."""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_bytes).hexdigest()


def load_pem_public_key(public_key_str: str):
    return serialization.load_pem_public_key(
        public_key_str.encode(), backend=default_backend()
    )


def export_public_key(public_key: rsa.RSAPublicKey):
    """Export the public key to PEM format"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def sign_message(message: str, counter, private_key: rsa.RSAPrivateKey):
    """Returns the signature after signing the message"""
    # Sign the message using the RSA-PSS scheme
    # Signature should be Base64 of data + counter
    message_bytes = message.encode() + str(counter).encode()
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def verify_signature(
    public_key: rsa.RSAPublicKey, signature: str, message: str, counter
):
    try:
        # Verify signature using sender's public key and the original message data
        message_bytes = message.encode() + str(counter).encode()
        public_key.verify(
            base64.b64decode(signature),
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
