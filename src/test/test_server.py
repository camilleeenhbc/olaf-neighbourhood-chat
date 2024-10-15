# src/test/test_server.py

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from aiohttp import web
from src.server import Server


@pytest.mark.asyncio
async def test_start():
    """Test that the server starts successfully."""
    server = Server(url="localhost:8000")

    with patch("src.server.websocket_server.serve") as mock_websocket_serve:
        mock_websocket_serve.return_value = AsyncMock()
        server.start_http_server = AsyncMock()

        await server.start()

        # Assert the WebSocket and HTTP servers are started
        mock_websocket_serve.assert_called_once_with(server.listen, "localhost", "8000")
        # server.start_http_server.assert_called_once_with("localhost", "9000")


@pytest.mark.asyncio
async def test_handle_message():
    """Test that the server correctly handles different message types."""
    server = Server(url="localhost:8000")
    websocket = AsyncMock()

    message = {"type": "client_list_request"}

    with patch.object(server, "send_client_list") as mock_send_client_list:
        await server.handle_message(websocket, message)
        mock_send_client_list.assert_called_once_with(websocket)


@pytest.mark.asyncio
async def test_connect_to_neighbour():
    """Test connecting to a neighbour server."""
    server = Server(url="localhost:8000")

    with patch("src.server.websockets.connect", new_callable=AsyncMock) as mock_connect:
        mock_websocket = AsyncMock()
        mock_connect.return_value = mock_websocket
        server.neighbourhood.add_active_server = AsyncMock()

        await server.connect_to_neighbour("localhost:9000")

        # Verify the connection attempt to the neighbor
        mock_connect.assert_called_once_with("ws://localhost:9000")
        server.neighbourhood.add_active_server.assert_called_once_with(
            "localhost:9000", mock_websocket
        )


@pytest.mark.asyncio
async def test_handle_file_upload(aiohttp_client, tmp_path):
    """Test the file upload functionality."""
    server = Server(url="localhost:8000")
    app = web.Application()
    app.router.add_post("/api/upload", server.handle_file_upload)

    client = await aiohttp_client(app)
    file_content = b"dummy content"
    file_path = tmp_path / "test.txt"
    file_path.write_bytes(file_content)

    data = {"file": open(file_path, "rb")}
    response = await client.post("/api/upload", data=data)
    assert response.status == 200

    json_response = await response.json()
    assert "file_url" in json_response["response"]["body"]
