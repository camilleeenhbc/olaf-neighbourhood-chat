import logging
import json
import websockets
import websockets.asyncio.server as websocket_server
from typing import List, Optional

from neighbourhood import Neighbourhood

logging.basicConfig(level=logging.INFO)


class Server:
    def __init__(self, address: str = "localhost", port: int = 80) -> None:
        self._websocket_server: Optional[websocket_server.Server] = None

        self.address = address
        self.port = port
        self.url = f"{address}:{port}"

        self.neighbour_servers = []
        self.neighbourhood = Neighbourhood(self.url)

        # TODO: Change to real list of client RSAs
        self.clients = [
            f"RSA1-{port}",
            f"RSA2-{port}",
        ]  # List of clients connecting to this server

    def add_neighbour_servers(self, server_urls: List[str]):
        self.neighbour_servers += server_urls

    async def connect_to_neighbourhood(self):
        for neighbour_url in self.neighbour_servers:
            if neighbour_url in self.neighbourhood.active_servers:
                continue

            try:
                websocket = await websockets.connect(f"ws://{neighbour_url}")
                self.neighbourhood.add_active_server(neighbour_url, websocket)
                logging.debug(f"{self.url} connect to neighbour {neighbour_url}")
            except Exception as e:
                logging.error(
                    f"{self.url} failed to connect to neighbour {neighbour_url}"
                )

    async def start(self):
        """
        Start the server which listens for message on the specified address and port
        """
        self._websocket_server = await websocket_server.serve(
            self.listen, self.address, self.port
        )
        await self.connect_to_neighbourhood()
        await self.request_client_update()
        await self._websocket_server.wait_closed()

    async def stop(self):
        logging.info(f"Closing {self.url}")
        self.clients = []
        await self.request_client_update()
        self._websocket_server.close()

    async def listen(self, websocket):
        """
        Listen and handle messages of type: signed_data, client_list_request,
        client_update_request, chat, hello, and public_chat
        """
        async for message in websocket:
            # logging.info(f"{self.url} receives message: {message}")
            message = json.loads(message)

            message_type = message.get("type", None)

            if message_type == "client_list_request":
                logging.info(f"{self.url} receives {message_type} message")
                await self.send_client_list(websocket)
            elif message_type == "client_update_request":
                logging.info(f"{self.url} receives {message_type} message")
                await self.send_client_update()
            elif message_type == "client_update":
                logging.info(f"{self.url} receives {message_type} message")
                await self.receive_client_update(websocket, message)
            elif message_type == "signed_data":
                # TODO: Handle counter and signature
                counter = message.get("counter", None)
                signature = message.get("signature", None)

                data = message.get("data", None)
                if data is None:
                    logging.error(
                        f"{self.url}: Type and data not found for this message: {message}"
                    )
                    continue

                # Handle chats
                message_type = data.get("type", None)
                logging.info(f"{self.url} receives {message_type} message")
                if message_type == "chat":
                    await self.receive_chat(data)
                elif message_type == "hello":
                    await self.receive_hello(data)
                elif message_type == "public_chat":
                    await self.receive_public_chat(data)
                else:
                    logging.error(
                        f"{self.url}: Type not found for this message: {message}"
                    )
            else:
                logging.error(f"{self.url}: Type not found for this message: {message}")

    async def send_message(self, websocket, message, request: bool):
        return await self.neighbourhood.send_message(websocket, message, request)

    async def receive_chat(self, message):
        pass

    async def receive_hello(self, message):
        client_public_key = message["public_key"]
        self.clients.append(client_public_key)
        await self.send_client_update()

    async def receive_public_chat(self, message):
        pass

    async def send_client_list(self, websocket):
        """(Between server and client) Provide the client the client list on all servers"""

        # Reformat the each server's client list
        servers = []
        for websocket, clients in self.neighbourhood.clients_across_servers.items():
            server_address = self.neighbourhood.active_servers.get(websocket, None)
            servers.append(
                {
                    "address": server_address,
                    "clients": clients,
                }
            )

        response = {
            "type": "client_list",
            "servers": servers,
        }
        await self.send_message(websocket, response, request=False)

    async def send_client_update(self):
        """
        (Between servers) Send client update to all active servers
        when a client sends `hello` or disconnects
        """
        response = {
            "type": "client_update",
            "clients": self.clients,
        }
        await self.neighbourhood.broadcast_message(response, request=False)

    async def request_client_update(self):
        """
        (Between servers) Send request client update to all servers.
        Expect to receive an updated client list for each server.
        """
        request = {
            "type": "client_update_request",
        }
        await self.neighbourhood.broadcast_message(request, request=True)

    async def receive_client_update(self, websocket, message):
        clients = message["clients"]
        # print(websocket.remote_address)
        # address, port = websocket.remote_address
        # server_url = f"{address}:{port}"
        server_url = self.neighbourhood.active_servers.get(websocket, None)
        logging.info(f"{self.url} receives client update from {server_url}: {clients}")
