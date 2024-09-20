import json
import logging
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

    async def broadcast_message(self, message):
        for neighbour_url, websocket in self.active_servers.items():
            try:
                await websocket.send(json.dumps(message))
                logging.info(
                    f"{self.server_url} broadcasted message to {neighbour_url}"
                )
            except Exception as e:
                logging.info(
                    f"{self.server_url} failed to broadcast message to {neighbour_url}: {e}"
                )

    def send_client_list(self):
        # send a list of all connected clients to server (requesting)
        response = {
            "type": "client_list",
            "servers": [
                {
                    "address": self.server_url, #server address
                    "clients": [
                        "<Exported RSA public key of client>",
                    ]
                },
            ]
        }
        pass

    def send_client_update(self):
        pass
