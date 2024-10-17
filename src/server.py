"""Contains a `Server` class"""

import asyncio
import json
import logging
import os
import uuid
from typing import Optional

import websockets
import websockets.asyncio.server as websocket_server
from aiohttp import web

from .server_as_client import ServerAsClient
from .utils import crypto

logging.basicConfig(format="%(levelname)s:\t%(message)s", level=logging.INFO)

UPLOAD_DIRECTORY = "files"
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)
MAX_FILE_SIZE = 50 * 1024 * 1024


class Server:
    """
    A server that talks to other servers, receives and sends client's messages
    """

    def __init__(self, url: str = "localhost:80") -> None:
        self._websocket_server: Optional[websocket_server.Server] = None
        self.url = url

        self.counter = 0
        self.private_key, self.public_key = crypto.generate_private_public_keys()

        # server address: {server public key, server counter}
        self.neighbour_servers = {}
        self.neighbour_websockets = {}  # Websocket (ServerConnection): Neighbour URL
        self.neighbourhood = ServerAsClient(self)

        # {websocket: {public_key, counter}}
        self.clients = {}

    async def add_neighbour_server(self, server_address: str, server_public_key: str):
        """Save the URL and public key of the neighbouring server

        Args:
            server_address (str): URL of the neighbouring server
            server_public_key (str): public key of the neighbouring server
        """
        if server_address not in self.neighbour_servers:
            self.neighbour_servers[server_address] = {
                "public_key": server_public_key,
                "counter": 0,
            }

            if self._websocket_server is not None:
                await self.connect_to_neighbour(server_address)

    async def connect_to_neighbourhood(self):
        """Create client connections for every neighbour servers"""
        for neighbour_url in self.neighbour_servers:
            await self.connect_to_neighbour(neighbour_url)

    async def connect_to_neighbour(self, neighbour_url):
        """
        Create a client connection to the neighbour server to send requests
        if the neighbour server hasn't already in the list of active servers
        """
        if neighbour_url in self.neighbourhood.active_servers.values():
            return

        try:
            websocket = await websockets.connect(f"ws://{neighbour_url}")
            await self.neighbourhood.add_active_server(neighbour_url, websocket)
            logging.info("%s connects to neighbour %s", self.url, neighbour_url)
        except Exception as e:
            logging.error(
                "%s failed to connect to neighbour %s: %s", self.url, neighbour_url, e
            )

    async def start(self):
        """
        Start the server which listens for message on the specified address and port
        """
        try:
            address, port = self.url.split(":")
            self._websocket_server = await websocket_server.serve(
                self.listen, address, port
            )

            await asyncio.gather(
                self.start_http_server(address, port),  # Start the HTTP server
                self.connect_to_neighbourhood(),  # Connect to neighbouring servers
                self.request_client_update(),
                self._websocket_server.wait_closed(),  # Request client updates
            )
        except Exception as e:
            logging.error("Error occurred in server: %s", e)
            await self.stop()

    async def stop(self):
        """Stop the server by sending empty client update and closing the websocket"""
        logging.info("Closing %s", self.url)
        self.clients = {}
        await self.send_client_update()

        if self._websocket_server:
            self._websocket_server.close()
            await self._websocket_server.wait_closed()

    async def listen(self, websocket: websocket_server.ServerConnection):
        """
        Listen and handle messages of type: signed_data, client_list_request,
        client_update_request, chat, hello, and public_chat
        """
        while True:
            try:
                message = await websocket.recv()
                await self.handle_message(websocket, message)
            except websockets.ConnectionClosed as e:
                logging.info("WebSocket connection closed: %s", e)
                break
            except RuntimeError as e:
                logging.error("Error in WebSocket connection: %s", e)
                break

        await self.remove_websocket(websocket)
        await websocket.close()

    async def remove_websocket(self, websocket):
        """Remove websocket from server/neighbourhood states"""
        if websocket in self.neighbour_websockets:
            neighbour_url = self.neighbour_websockets.pop(websocket)
            self.neighbourhood.remove_active_server(neighbour_url)
            logging.info("%s removes neighbour websocket: %s", self.url, neighbour_url)
        elif websocket in self.clients:
            self.clients.pop(websocket)
            logging.info("%s removes client", self.url)
            await self.send_client_update()

    async def handle_message(
        self, websocket: websocket_server.ServerConnection, message_str
    ):
        """
        Handle messages of type: signed_data, client_list_request,
        client_update_request, chat, hello, and public_chat
        """
        message = (
            json.loads(message_str) if isinstance(message_str, str) else message_str
        )
        message_type = message.get("type", None)

        if message_type == "client_list_request":
            await self.send_client_list(websocket)
        elif message_type == "client_update_request":
            await self.send_client_update(websocket)
        elif message_type == "client_update":
            self.receive_client_update(websocket, message)
        elif message_type == "signed_data":
            counter = message.get("counter", None)
            signature = message.get("signature", None)
            if counter is None or signature is None:
                logging.error(
                    "Cannot find counter or signature in this message: %s", message
                )
                return

            data = message.get("data", None)
            if data is None:
                logging.error(
                    "%s: Cannot find `data` field for this message: %s",
                    self.url,
                    message,
                )
                return

            # Verify the signature if the client is known
            if websocket in self.clients:
                public_key = self.clients[websocket]["public_key"]
                public_key = crypto.load_pem_public_key(public_key)

                if not crypto.verify_signature(public_key, signature, data, counter):
                    logging.error(
                        "%s message with invalid signature detected: %s",
                        self.url,
                        message_str,
                    )
                    return

            data = json.loads(data) if isinstance(data, str) else data

            message["data"] = data  # Ensure data is parsed JSON object

            # Further processing based on `data["type"]`
            message_type = data.get("type", None)
            logging.info("%s receives %s message", self.url, message_type)
            if message_type == "chat":
                await self.receive_chat(websocket, message)
            elif message_type == "hello":
                await self.receive_hello(websocket, data)
            elif message_type == "public_chat":
                await self.receive_public_chat(websocket, message)
            elif message_type == "server_hello":
                await self.receive_server_hello(websocket, message)
            else:
                logging.error(
                    "%s: Type not found for this message: %s", self.url, message
                )
        else:
            logging.error("%s: Type not found for this message: %s", self.url, message)

    async def send_response(
        self, websocket: websocket_server.ServerConnection, message
    ):
        """Send message as a respond to the corresponding client/server connection"""
        try:
            await websocket.send(json.dumps(message))
        except (websockets.ConnectionClosed, TypeError) as e:
            logging.error("%s failed to send response: %s", self.url, e)

    async def receive_server_hello(self, websocket, message):
        """Handle `server_hello` message type"""
        counter = int(message.get("counter", "0"))
        signature = message.get("signature", None)
        data = message.get("data", {})

        # Validate counter
        sender_address = data["sender"]

        recorded_counter = self.neighbour_servers[sender_address].get("counter", 0)
        if counter < recorded_counter:
            logging.error("%s receives server_hello with wrong counter", self.url)
            return

        self.neighbour_servers[sender_address]["counter"] = recorded_counter

        # Verify signature
        public_key = self.neighbour_servers[sender_address].get("public_key", None)
        public_key = crypto.load_pem_public_key(public_key)
        if not crypto.verify_signature(
            public_key, signature, json.dumps(data), counter
        ):
            logging.error("%s cannot verify signature for server_hello", self.url)
            return

        logging.info("%s accepts server hello from %s", self.url, sender_address)
        # Map the server connection to this address and establish a client connection
        self.neighbour_websockets[websocket] = sender_address
        await self.connect_to_neighbour(sender_address)

    def validate_client_counter(self, websocket, message):
        """Validate the counter found in the message"""
        sender = self.clients.get(websocket)
        if not sender:
            logging.error("%s message from unknown client detected", self.url)
            return False

        # Check if the counter is larger or equal to the counter saved in the server
        sender["counter"] = sender.get("counter", "0")
        if int(message["counter"]) < int(sender["counter"]):
            logging.error("%s message with replay attack detected", self.url)
            return False

        # Increment counter
        self.clients[websocket]["counter"] = int(message["counter"]) + 1
        return True

    def get_websocket_from_fingerprint(self, fingerprint):
        """
        Retrieve a public key using the sender's fingerprint from the online users list.
        """
        for websocket, client in self.clients.items():
            # Assuming the client entry contains the public key in PEM format
            public_key_pem = client.get("public_key", None)
            if public_key_pem is None:
                continue

            public_key = crypto.load_pem_public_key(public_key_pem)
            client_fingerprint = crypto.generate_fingerprint(public_key)
            if client_fingerprint == fingerprint:
                return websocket
        return None

    async def receive_chat(self, websocket, message):
        """Handle receiving `chat` message type"""
        data = message.get("data")
        if isinstance(data, str):
            data = json.loads(data)
        destination_servers = data.get("destination_servers", [])
        if len(destination_servers) == 0:
            logging.error("%s receives invalid chat message: %s", self.url, message)

        # If this is the server of the sender
        if websocket in self.clients:
            if not self.validate_client_counter(websocket, message):
                return

            # Forward the message to destination servers
            for server_url in destination_servers:
                # Handle chat message in the destination server
                if server_url == self.url:
                    continue

                websocket = self.neighbourhood.find_active_server(server_url)
                if websocket is None:
                    logging.error(
                        "%s cannot find destination server %s", self.url, server_url
                    )
                    continue

                logging.info("%s forwards private chat to %s", self.url, server_url)
                await self.neighbourhood.send_request(websocket, message)

        # Handle chat message in the destination server
        if self.url in destination_servers:
            logging.info("%s receives chat as the destination server", self.url)

            for client_websocket in self.clients:
                await self.send_response(client_websocket, message)

    async def receive_hello(self, websocket, message):
        """Save client's public key and send client update to other servers"""
        client_public_key = message["public_key"]
        logging.info("%s receives hello from client", self.url)
        self.clients[websocket] = {
            "public_key": client_public_key,
        }
        await self.send_client_update()

    async def receive_public_chat(self, websocket, request):
        """
        Receive public chats and braodcast to connected
        clients and other neighbourhoods if valid message
        """
        logging.info("%s received public chat message", self.url)

        fingerprint = request["data"].get("sender", None)
        message = request["data"].get("message", None)
        counter = request.get("counter", None)
        if counter is None or fingerprint is None or message is None:
            logging.error("%s received an invalid public_chat message", self.url)
            return

        sender = self.clients.get(websocket, None)
        if sender is not None and not self.validate_client_counter(websocket, request):
            return

        # send to clients in the server
        for client in self.clients:
            if client == websocket:
                continue

            await self.send_response(client, request)

        # request neighborhoods broadcast message
        if sender:
            await self.neighbourhood.broadcast_request(request)

    async def send_client_list(self, websocket):
        """(Between server and client) Provide the client the client list on all servers"""
        logging.info("%s sends client list", self.url)

        all_clients = self.neighbourhood.clients_across_servers
        # Reformat the each server's client list
        servers = []
        for server_address, clients in all_clients.items():
            servers.append(
                {
                    "address": server_address,
                    "clients": clients,
                }
            )

        servers.append(
            {
                "address": self.url,
                "clients": [client["public_key"] for client in self.clients.values()],
            }
        )

        response = {
            "type": "client_list",
            "servers": servers,
        }
        await self.send_response(websocket, response)

    async def send_client_update(self, websocket=None):
        """
        (Between servers) If websocket is None, send client update to all active servers
        when a client sends `hello` or disconnects.
        Otherwise, send to the specified websocket
        """
        public_keys = [client["public_key"] for client in self.clients.values()]

        response = {
            "type": "client_update",
            "clients": public_keys,
        }

        if websocket is None:
            logging.info("%s sends client update to all servers", self.url)
            await self.neighbourhood.broadcast_request(response)
        else:
            neighbour_url = self.neighbour_websockets[websocket]
            logging.info("%s sends client update to %s", self.url, neighbour_url)
            await self.send_response(websocket, response)

    async def request_client_update(self):
        """
        (Between servers) Send request client update to all servers.
        Expect to receive an updated client list for each server.
        """
        logging.info("%srequests client update from all servers", self.url)

        request = {
            "type": "client_update_request",
        }
        responses = await self.neighbourhood.broadcast_request(request, True)

        # Receive client_update response from other servers
        for websocket, message in responses.items():
            self.receive_client_update(websocket, message)

    def receive_client_update(self, websocket, message):
        """Handle `client_update` message type"""
        clients = message["clients"]
        if websocket in self.neighbour_websockets:
            neighbour_url = self.neighbour_websockets[websocket]
        elif websocket in self.neighbourhood.active_servers:
            neighbour_url = self.neighbourhood.active_servers[websocket]
        else:
            logging.error("%s receives client_update from invalid websocket", self.url)
            return

        logging.info("%s receives client update from %s", self.url, neighbour_url)
        self.neighbourhood.save_clients(neighbour_url, clients)

    async def start_http_server(self, address, port: int):
        """Start the HTTP server for handling file uploads"""
        app = web.Application()
        app.router.add_post(
            "/api/upload", self.handle_file_upload
        )  # HTTP POST route for file upload
        app.router.add_get("/{filename}", self.handle_download)

        runner = web.AppRunner(app)
        await runner.setup()
        http_port = int(port) + 1000
        site = web.TCPSite(runner, address, http_port)
        await site.start()

        # Confirm server is running and log the port
        logging.info("HTTP server running on port: %s", str(http_port))

    async def handle_file_upload(self, request):
        """Handle file upload via HTTP POST"""
        logging.info("Server handles file upload")
        reader = await request.multipart()

        # Process file part
        field = await reader.next()
        if field.name == "file":
            filename = field.filename
            file_extension = os.path.splitext(filename)[1]  # Get file extension
            unique_id = str(uuid.uuid4())  # Generate unique UUID

            # Append UUID to filename
            unique_filename = (
                f"{os.path.splitext(filename)[0]}-{unique_id}{file_extension}"
            )
            file_path = os.path.join(UPLOAD_DIRECTORY, unique_filename)

            size = 0
            # Write the file to the server's upload directory
            with open(file_path, "wb") as f:
                while True:
                    chunk = await field.read_chunk()  # Read the file chunk by chunk
                    if not chunk:
                        break

                    # Check file size
                    size += len(chunk)
                    if size > MAX_FILE_SIZE:
                        return web.Response(
                            status=413, text="File size exceeds the limit."
                        )

                    f.write(chunk)

            logging.info("File %s saved at %s", filename, file_path)

            file_url = f"{request.url.scheme}://{request.url.host}:{request.url.port}/{unique_id}"
            return web.json_response({"response": {"body": {"file_url": file_url}}})
        return web.Response(status=400, text="No file found in request.")

    async def handle_download(self, request):
        """Handle file downloads via HTTP GET."""
        unique_id = request.match_info.get("filename", None)

        if not unique_id:
            return web.Response(status=400, text="Unique ID not specified.")

        # Search for any file in the directory that contains the unique ID
        for filename in os.listdir(UPLOAD_DIRECTORY):
            if unique_id in filename:
                file_path = os.path.join(UPLOAD_DIRECTORY, filename)
                # Set headers to prompt download with the original filename
                original_filename = (
                    filename.split(f"-{unique_id}")[0] + os.path.splitext(filename)[1]
                )
                return web.FileResponse(
                    file_path,
                    headers={
                        "Content-Disposition": f'attachment; filename="{original_filename}"'
                    },
                )

        return web.Response(status=404, text="File not found.")
