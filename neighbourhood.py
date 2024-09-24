import json
import logging
import asyncio
from websockets import WebSocketClientProtocol
from typing import List

logging.basicConfig(level=logging.INFO)


class Neighbourhood:
    def __init__(self, server_url) -> None:
        # List of all connected clients on all servers.
        # Format: {websocket1: ["RSA1", "RSA2"], websocket2: ["RSA3"]}
        self.clients_across_servers = {}

        # self.server_url = server_url  # URL of the current server
        self.active_servers = {}  # URL: Websocket of the active neighbour servers

    def add_active_server(self, server_url: str, websocket: WebSocketClientProtocol):
        self.active_servers[websocket] = server_url

    def remove_active_server(self, websocket: WebSocketClientProtocol):
        self.active_servers.pop(websocket)

    def save_clients(self, websocket: WebSocketClientProtocol, client_list: List[str]):
        server_url = self.active_servers.get(websocket, None)
        if server_url is None:
            logging.error("Cannot find server URL for the websocket")
            return

        self.clients_across_servers[websocket] = client_list

    async def send_message(self, receiver_websocket, message, request: bool):
        """Send message to a specific websocket"""
        if receiver_websocket is None:
            logging.error(f"failed to send message: Receiver isn't active")
            return

        try:
            await receiver_websocket.send(json.dumps(message))
            if request is True:
                return await receiver_websocket.recv()
        except Exception as e:
            logging.info(f"failed to send message: {e}")

    async def broadcast_message(self, message, request: bool = True):
        """Broadcast the specified message to all active servers"""
        tasks = []
        for neighbour_url, websocket in self.active_servers.items():
            tasks.append(
                asyncio.create_task(self.send_message(websocket, message, request))
            )

        futures = await asyncio.gather(*tasks)
        logging.info(f"Broadcasting received: {futures}")
