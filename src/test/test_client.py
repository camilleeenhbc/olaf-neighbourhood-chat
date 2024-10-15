# src/test/test_client.py

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, patch, MagicMock
from src.utils.crypto import generate_fingerprint, load_pem_public_key
from src.client import Client
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


@pytest.mark.asyncio
async def test_connect_to_server():
    # Setup
    client = Client("localhost:8080")
    with patch("src.client.connect", new_callable=AsyncMock) as mock_connect:
        with patch(
            "src.client.Client.request_client_list", new_callable=AsyncMock
        ) as mock_request:
            # mock WebSocket connection
            mock_ws = AsyncMock()
            mock_connect.return_value = mock_ws
            mock_request.return_value = None

            await client.connect_to_server()
            mock_connect.assert_called_once_with("ws://localhost:8080")
            mock_ws.send.assert_called_once()
            mock_request.assert_called_once()


@pytest.mark.asyncio
async def test_sign_message():
    # Setup
    client = Client("localhost:8080")
    message = "test message"
    counter = 0

    # Act
    signature = client.sign_message(message)

    # Assert
    assert signature is not None


def test_get_public_key_from_fingerprint():
    # Setup
    client = Client("localhost:8080")

    # Create a mock public key and fingerprint
    public_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    ).public_key()

    fingerprint = generate_fingerprint(public_key)

    # Manually add to the client’s online users
    client.online_users["localhost:8081"] = [
        {"public_key": public_key, "fingerprint": fingerprint}
    ]

    # Act
    server, key = client.get_public_key_from_fingerprint(fingerprint)

    # Assert
    assert server == "localhost:8081"
    assert key == public_key


@pytest.mark.asyncio
async def test_receive_message():
    client = Client("localhost:8080")
    mock_data = {
        "type": "client_list",
        "servers": [{"address": "localhost:8081", "clients": ["mock_public_key"]}],
    }

    with patch(
        "src.utils.crypto.load_pem_public_key", return_value=MagicMock()
    ) as mock_load_key:
        client.handle_client_list = MagicMock()
        await client.receive_message(mock_data)

        client.handle_client_list.assert_called_once_with(mock_data)


@pytest.mark.asyncio
async def test_handle_public_chat():
    client = Client("localhost:8080")

    # Mock online users
    mock_public_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    ).public_key()

    mock_fingerprint = generate_fingerprint(mock_public_key)
    client.online_users = {
        "localhost:8081": [
            {"public_key": mock_public_key, "fingerprint": mock_fingerprint}
        ]
    }

    with patch("src.utils.crypto.verify_signature", return_value=True):
        mock_message = {
            "type": "public_chat",
            "sender": mock_fingerprint,
            "message": "Hello world",
        }

        await client.handle_public_chat("mock_signature", mock_message, client.counter)

    # No exception raised means test passed
