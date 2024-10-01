import json
import logging
import src.utils.crypto as crypto

from websockets import WebSocketClientProtocol
from typing import List

logging.basicConfig(format="%(levelname)s:\t%(message)s", level=logging.INFO)


class ServerAsClient:
    def __init__(self, server) -> None:
        self.server = server
        self.server_url = server.url

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

    def remove_active_server(self, server_url: str):
        websocket = self.find_active_server(server_url)
        if websocket is None:
            logging.error(f"Cannot find neighbour {server_url}")
        else:
            self.active_servers.pop(websocket)

    def find_active_server(self, server_url) -> WebSocketClientProtocol:
        for websocket, url in self.active_servers.items():
            if url == server_url:
                return websocket

        return None

    def save_clients(self, server_url: str, client_list: List[str]):
        self.clients_across_servers[server_url] = client_list

    async def send_request(
        self,
        receiver_websocket: WebSocketClientProtocol,
        message,
        wait_for_response: bool = False,
    ):
        """Send request to a specific websocket"""
        response = None
        try:
            await receiver_websocket.send(json.dumps(message))
            if wait_for_response is True:
                response = await receiver_websocket.recv()
                response = json.loads(response)

        except Exception as e:
            logging.error(f"{self.server_url} failed to send request: {e}")

        return response

    async def broadcast_request(self, message, wait_for_response: bool = False):
        """Broadcast the specified request to all active servers"""
        responses = {}
        for websocket in self.active_servers.keys():
            response = await self.send_request(websocket, message, wait_for_response)
            responses[websocket] = response

        return responses

    async def send_server_hello(self, websocket: WebSocketClientProtocol):
        logging.info(f"{self.server_url} sends server_hello")
        data = {
            "type": "server_hello",
            "sender": self.server_url,
        }

        self.server.counter += 1

        request = {
            "type": "signed_data",
            "data": data,
            "counter": self.server.counter,
            "signature": crypto.sign_message(
                json.dumps(data), self.server.counter, self.server.private_key
            ),
        }

        await self.send_request(websocket, request)
