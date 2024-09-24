import json
import logging
import asyncio
from websockets import WebSocketClientProtocol

logging.basicConfig(level=logging.INFO)


class Neighbourhood:
    def __init__(self, server_url) -> None:
        self.clients = [
            "RSA public keys"
        ]  # List of connected clients in the neighbourhood
        self.server_url = server_url  # URL of the current server
        self.active_servers = {}  # URL: Websocket of the active neighbour servers

    def add_active_server(self, server_url: str, websocket: WebSocketClientProtocol):
        self.active_servers[server_url] = websocket

    def remove_active_server(self, server_url: str):
        self.active_servers.pop(server_url)

    async def send_message(self, websocket, message, request: bool):
        """Send message to a specific websocket"""
        if websocket is None:
            logging.error(
                f"{self.server_url} failed to send message: Receiver isn't active"
            )
            return

        try:
            await websocket.send(json.dumps(message))
            # logging.info(f"{self.server_url} sent message to {receiver_url}")
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

    async def send_client_update(self):
        """
        (Between servers) Send client update to all active servers
        when a client sends `hello` or disconnects
        """
        response = {
            "type": "client_update",
            "clients": [
                "<Exported RSA public key of client>",
            ],
        }
        await self.broadcast_message(response, request=False)

    async def request_client_update(self):
        """
        (Between servers) Send request client update to all servers.
        Expect to receive an updated client list for each server.
        """
        request = {
            "type": "client_update_request",
        }
        client_lists = await self.broadcast_message(request, request=True)
        logging.info(f"{self.server_url} receives client list: {client_lists}")
        # for client_list in client_lists:
        #     logging.info(f"{self.server_url} receives client list: {client_list}")
