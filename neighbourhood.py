import json
import logging
import asyncio
from websockets import WebSocketClientProtocol

logging.basicConfig(level=logging.INFO)


class Neighbourhood:
    def __init__(self, server_url) -> None:
        self.server_url = server_url  # URL of the current server
        self.active_servers = {}  # URL: Websocket of the active neighbour servers

    def add_active_server(self, server_url: str, websocket: WebSocketClientProtocol):
        self.active_servers[server_url] = websocket

    def remove_active_server(self, server_url: str):
        self.active_servers.pop(server_url)

    async def send_message(self, receiver_url, message):
        """Send message to a specific server"""
        websocket = self.active_servers.get(receiver_url, None)
        if websocket is None:
            logging.error(
                f"{self.server_url} failed to send message: Server {receiver_url} isn't active"
            )
            return

        try:
            await websocket.send(json.dumps(message))
            logging.info(f"{self.server_url} broadcasted message to {receiver_url}")
        except Exception as e:
            logging.info(
                f"{self.server_url} failed to send message to {receiver_url}: {e}"
            )

    async def broadcast_message(self, message):
        """Broadcast the specified message to all active servers"""
        tasks = []
        for neighbour_url in self.active_servers:
            tasks.append(asyncio.create_task(self.send_message(neighbour_url, message)))

        asyncio.gather(*tasks)

    async def send_client_list(self):
        # send a list of all connected clients to server (requesting)
        response = {
            "type": "client_list",
            "servers": [
                {
                    "address": self.server_url,  # server address
                    "clients": [
                        "<Exported RSA public key of client>",
                    ],
                },
            ],
        }
        await self.broadcast_message(response)

    async def send_client_update(self):
        """Send client update when a client sends `hello` or disconnects"""
        response = {
            "type": "client_update",
            "clients": [
                "<Exported RSA public key of client>",
            ],
        }
        await self.broadcast_message(response)
