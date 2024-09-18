import logging
import json
import websockets
from websockets.asyncio.server import serve
from typing import List
from neighbourhood import Neighbourhood

logging.basicConfig(level=logging.INFO)


class Server:
    def __init__(self, address: str = "localhost", port: int = 80) -> None:
        self.address = address
        self.port = port
        self.neighbour_servers = []
        self.neighbourhood = Neighbourhood()

    def add_servers(self, server_urls: List[str]):
        self.neighbour_servers += server_urls

    async def start(self):
        """
        Start the server which listens for message on the specified address and port
        """
        server = await serve(self.listen, self.address, self.port)
        logging.info(f"Server starts on port {self.port}")
        await server.wait_closed()

    async def listen(self, websocket):
        """
        Listen and handle messages of type: signed_data, client_list_request,
        client_update_request, chat, hello, and public_chat
        """
        async for message in websocket:
            logging.info(f"Receive message: {message}")
            message = json.loads(message)

            message_type = message.get("type", None)

            if message_type == "client_list_request":
                self.neighbourhood.send_client_list()
            elif message_type == "client_update_request":
                self.neighbourhood.send_client_update()
            elif message_type == "signed_data":
                # TODO: Handle counter and signature
                counter = message.get("counter", None)
                signature = message.get("signature", None)

                data = message.get("data", None)
                if data is None:
                    logging.error(
                        f"Type and data not found for this message: {message}"
                    )
                    continue

                # Handle chats
                message_type = data.get("type", None)
                if message_type == "chat":
                    self.receive_chat(data)
                elif message_type == "hello":
                    self.receive_hello(data)
                elif message_type == "public_chat":
                    self.receive_public_chat(data)
                else:
                    logging.error(f"Type not found for this message: {message}")
            else:
                logging.error(f"Type not found for this message: {message}")

    def receive_chat(self, message):
        pass

    def receive_hello(self, message):
        pass

    def receive_public_chat(self, message):
        pass
