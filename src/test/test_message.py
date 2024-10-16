# src/test/test_message.py

import base64
import json

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from src.utils.message import Message


# Generate RSA keys for testing
@pytest.fixture
def rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # modulus length
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key


def test_encrypt_key(rsa_keys):
    private_key, public_key = rsa_keys
    aes_key = b"thisisatestkey123"  # 16 bytes for AES-128

    encrypted_key = Message.encrypt_key(public_key, aes_key)
    assert isinstance(encrypted_key, str)  # Encrypted AES key should be base64 encoded

    decrypted_key = Message.decrypt_key(private_key, encrypted_key)
    assert (
        decrypted_key == aes_key
    )  # The decrypted key should match the original AES key


def test_encrypt_chat_message(rsa_keys):
    _, public_key = rsa_keys
    message = Message(content="Hello, this is a test chat message.")

    # Encrypt the message
    message.encrypt_chat_message([public_key])

    # Check that encryption produced an IV and encrypted content
    assert message.iv is not None
    assert message.encrypted_content is not None
    assert len(message.symm_keys) == 1  # Should contain one encrypted AES key


def test_encrypt_decrypt_message():
    # Generate RSA keys for encryption/decryption of AES key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Initialize message and perform encryption
    message_content = "Hello, this is a test chat message."
    message = Message(content=message_content)
    message.encrypt_chat_message([public_key])
    encrypted_message = Message(
        content=base64.b64encode(message.encrypted_content).decode()
    )

    # Decrypt the message with the corresponding private key
    decrypted_content = encrypted_message.decrypt_with_aes(
        private_key, message.symm_keys[0], message.iv
    )

    # Verify the decryption was successful and content matches
    assert decrypted_content is not None, "Decryption failed and returned None"
    decrypted_content_json = json.loads(decrypted_content)
    assert decrypted_content_json["message"] == message_content


def test_prepare_chat_message(rsa_keys):
    _, public_key = rsa_keys
    message_content = "Test chat message content"
    participants = ["Alice", "Bob"]
    destination_servers = ["localhost:8080"]

    # Set up the message
    message = Message(content=message_content)
    chat_message = message.prepare_chat_message(
        recipient_public_keys=[public_key],
        destination_servers=destination_servers,
        participants=participants,
    )

    # Verify chat message structure
    assert chat_message["type"] == "chat"
    assert chat_message["destination_servers"] == destination_servers
    assert "iv" in chat_message
    assert "symm_keys" in chat_message
    assert "chat" in chat_message
    assert len(chat_message["symm_keys"]) == 1

    # Verify that the encrypted content is base64 encoded
    encrypted_content = base64.b64decode(chat_message["chat"])
    assert isinstance(encrypted_content, bytes)

    # Verify IV is base64 encoded
    iv = base64.b64decode(chat_message["iv"])
    assert isinstance(iv, bytes)
    assert len(iv) == 16  # GCM mode IV is typically 16 bytes
