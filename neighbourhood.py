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

        # Format: Websocket (ClientProtocol): neighbour URL
        self.active_servers = {}

    async def add_active_server(
        self, server_url: str, websocket: WebSocketClientProtocol
    ):
        """Store the server websocket and url in the neighbourhood and send server_hello"""
        self.active_servers[websocket] = server_url
        await self.send_server_hello(websocket)

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
            logging.error(f"{self.server_url} failed to send request: {message} {e}")

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

    async def send_server_hello(self, websocket: WebSocketClientProtocol):
        logging.info(f"{self.server_url} sends server_hello")
        request = {
            "type": "signed_data",
            "data": {
                "type": "server_hello",
                "sender": self.server_url,
            },
            "counter": 0,
            "signature": "",
        }

        await self.send_request(websocket, request)
