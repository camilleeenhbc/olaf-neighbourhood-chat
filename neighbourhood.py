import json
import logging
import asyncio
from websockets import WebSocketClientProtocol
from typing import List

logging.basicConfig(level=logging.INFO)


class Neighbourhood:
    def __init__(self, server_url) -> None:
        self.server_url = server_url

        # List of all connected clients on all servers.
        # Format: {server_url1: ["RSA1", "RSA2"], server_url2: ["RSA3"]}
        self.clients_across_servers = {}

        # Format: neighbour url: Websocket (ClientProtocol)
        self.active_servers = {}

    def add_active_server(self, server_url: str, websocket: WebSocketClientProtocol):
        self.active_servers[websocket] = server_url

    def remove_active_server(self, websocket: WebSocketClientProtocol):
        self.active_servers.pop(websocket)

    def save_clients(self, server_url: str, client_list: List[str]):
        self.clients_across_servers[server_url] = client_list

    async def send_request(
        self,
        receiver_websocket: WebSocketClientProtocol,
        message,
        wait_for_response: bool = False,
    ):
        """Send request to a specific websocket"""
        try:
            await receiver_websocket.send(json.dumps(message))
            if wait_for_response is True:
                message = await receiver_websocket.recv()
                logging.info(f"{self.server_url} receives: {message}")
                return message
        except Exception as e:
            logging.info(f"{self.server_url} failed to send request: {e}")

    async def broadcast_request(self, message, wait_for_response: bool = False):
        """Broadcast the specified request to all active servers"""
        tasks = []
        for websocket in self.active_servers.keys():
            tasks.append(
                asyncio.create_task(
                    self.send_request(websocket, message, wait_for_response)
                )
            )

        responses = await asyncio.gather(*tasks)
        if wait_for_response is True:
            return responses
