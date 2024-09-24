import json
import logging
import asyncio
from websockets import WebSocketClientProtocol

logging.basicConfig(level=logging.INFO)


class Neighbourhood:
    def __init__(self, server_url) -> None:
        # List of all connected clients on all servers.
        # Format: {websocket1: ["RSA1", "RSA2"], websocket2: ["RSA3"]}
        self.clients_across_servers = {}

        self.server_url = server_url  # URL of the current server
        self.active_servers = {}  # URL: Websocket of the active neighbour servers

    def add_active_server(self, server_url: str, websocket: WebSocketClientProtocol):
        self.active_servers[server_url] = websocket

    def remove_active_server(self, server_url: str):
        self.active_servers.pop(server_url)

    def get_flatten_clients(self):
        clients = []
        for client_list in self.clients_across_servers.values():
            clients += client_list
        return clients

    async def send_message(self, websocket, message, request: bool):
        """Send message to a specific websocket"""
        if websocket is None:
            logging.error(
                f"{self.server_url} failed to send message: Receiver isn't active"
            )
            return

        try:
            await websocket.send(json.dumps(message))
            if request is True:
                return await websocket.recv()
        except Exception as e:
            logging.info(f"{self.server_url} failed to send message: {e}")

    async def broadcast_message(self, message, request: bool = True):
        """Broadcast the specified message to all active servers"""
        tasks = []
        for neighbour_url, websocket in self.active_servers.items():
            tasks.append(
                asyncio.create_task(self.send_message(websocket, message, request))
            )

        futures = await asyncio.gather(*tasks)
        logging.info(f"Broadcasting received: {futures}")
