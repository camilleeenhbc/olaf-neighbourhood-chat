import logging
import sys
import json
import os
import src.utils.crypto as crypto
import base64
import asyncio
import uuid
import websockets
import websockets.asyncio.server as websocket_server
from typing import List, Optional
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from src.server_as_client import ServerAsClient
from src.utils.message import Message

logging.basicConfig(format="%(levelname)s:\t%(message)s", level=logging.INFO)

UPLOAD_DIRECTORY = "files"
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)
MAX_FILE_SIZE = 50 * 1024 * 1024


class Server:
    def __init__(self, url: str = "localhost:80") -> None:
        self._websocket_server: Optional[websocket_server.Server] = None

        self.url = url

        self.counter = 0
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # modulus length
            backend=default_backend(),
        )
        self.public_key = crypto.load_pem_public_key(
            crypto.export_public_key(self.private_key.public_key())
        )

        # server address: {server public key, server counter}
        self.neighbour_servers = {}
        self.neighbour_websockets = {}  # Websocket (ServerConnection): Neighbour URL
        self.neighbourhood = ServerAsClient(self)

        # {websocket: {public_key, counter}}
        self.clients = {}

    async def add_neighbour_server(self, server_address: str, server_public_key: str):
        if server_address not in self.neighbour_servers:
            self.neighbour_servers[server_address] = {
                "public_key": server_public_key,
                "counter": 0,
            }

            if self._websocket_server is not None:
                await self.connect_to_neighbour(server_address)

    async def connect_to_neighbourhood(self):
        """Create client connections for every neighbour servers"""
        logging.info(self.neighbour_servers)
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
            logging.info(f"{self.url} connects to neighbour {neighbour_url}")
        except Exception as e:
            logging.error(
                f"{self.url} failed to connect to neighbour {neighbour_url}: {e}"
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
            logging.error(f"Error occurred in server: {e}")
            await self.stop()

    async def stop(self):
        logging.info(f"Closing {self.url}")
        self.clients = {}
        await self.send_client_update()

        self._websocket_server.close()
        await self._websocket_server.wait_closed()

    async def listen(self, websocket):
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
            # except Exception as e:
            #     logging.error("Error in WebSocket connection: %s", e)
            #     break

        await self.remove_websocket(websocket)
        await websocket.close()

    async def remove_websocket(self, websocket):
        """Remove websocket from server/neighbourhood states"""
        if websocket in self.neighbour_websockets:
            neighbour_url = self.neighbour_websockets.pop(websocket)
            self.neighbourhood.remove_active_server(neighbour_url)
            logging.info(f"{self.url} removes neighbour websocket: {neighbour_url}")
        elif websocket in self.clients:
            self.clients.pop(websocket)
            logging.info(f"{self.url} removes client")
            await self.send_client_update()

    async def handle_message(
        self, websocket: websocket_server.ServerConnection, message_str
    ):
        """
        Handle messages of type: signed_data, client_list_request,
        client_update_request, chat, hello, and public_chat
        """
        message = json.loads(message_str)

        message_type = message.get("type", None)

        if message_type == "client_list_request":
            await self.send_client_list(websocket)
        elif message_type == "client_update_request":
            await self.send_client_update(websocket)
        elif message_type == "client_update":
            self.receive_client_update(websocket, message)
        elif message_type == "signed_data":
            # TODO: Handle counter and signature
            counter = message.get("counter", None)
            signature = message.get("signature", None)

            if counter is None or signature is None:
                logging.error(
                    f"Cannot find counter or signature in this message: {message}"
                )
                return

            data = message.get("data", None)
            if data is None:
                logging.error(
                    f"{self.url}: Cannot find `data` field for this message: {message}"
                )
                return

            if websocket in self.clients:
                public_key = self.clients[websocket]["public_key"]
                public_key = crypto.load_pem_public_key(public_key)
                if not crypto.verify_signature(
                    public_key, signature, json.dumps(data), counter
                ):
                    logging.error(
                        f"{self.url} message with invalid signature detected: {message_str}"
                    )
                    return

            if isinstance(data, str):
                data = json.loads(data)

            message["data"] = data

            # Handle chats
            message_type = data.get("type", None)
            logging.info(f"{self.url} receives {message_type} message")
            if message_type == "chat":
                await self.receive_chat(websocket, message)
            elif message_type == "hello":
                await self.receive_hello(websocket, data)
            elif message_type == "public_chat":
                await self.receive_public_chat(websocket, message)
            elif message_type == "server_hello":
                await self.receive_server_hello(websocket, message)
            else:
                logging.error(f"{self.url}: Type not found for this message: {message}")
        else:
            logging.error(f"{self.url}: Type not found for this message: {message}")

    async def send_response(
        self, websocket: websocket_server.ServerConnection, message
    ):
        try:
            await websocket.send(json.dumps(message))
        except Exception as e:
            logging.error(f"{self.url} failed to send response: {e}")

    async def receive_server_hello(self, websocket, message):
        counter = int(message.get("counter", "0"))
        signature = message.get("signature", None)
        data = message.get("data", {})

        # Validate counter
        sender_address = data["sender"]

        recorded_counter = self.neighbour_servers[sender_address].get("counter", 0)
        if counter < recorded_counter:
            logging.error(f"{self.url} receives server_hello with wrong counter")
            return

        self.neighbour_servers[sender_address]["counter"] = recorded_counter

        # Verify signature
        public_key = self.neighbour_servers[sender_address].get("public_key", None)
        public_key = crypto.load_pem_public_key(public_key)
        if not crypto.verify_signature(public_key, signature, data, counter):
            logging.error(f"{self.url} cannot verify signature for server_hello")
            return

        logging.info(f"{self.url} Accepts server hello from {sender_address}")
        # Map the server connection to this address and establish a client connection
        self.neighbour_websockets[websocket] = sender_address
        await self.connect_to_neighbour(sender_address)

    def validate_client_counter(self, websocket, message):
        sender = self.clients.get(websocket)
        if not sender:
            logging.error(f"{self.url} message from unknown client detected")
            return False

        # Check if the counter is larger or equal to the counter saved in the server
        sender["counter"] = sender.get("counter", "0")
        if int(message["counter"]) < int(sender["counter"]):
            logging.error(f"{self.url} message with replay attack detected")
            return False

        # Increment counter
        sender["counter"] = int(message["counter"]) + 1
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

    # recieve private chat
    async def receive_chat(self, websocket, message):
        destination_servers = message["data"].get("destination_servers", [])
        if destination_servers is None:
            logging.error(f"{self.url} receives invalid chat message: {message}")

        if self.url not in destination_servers and not self.validate_client_counter(
            websocket, message
        ):
            return

        # Handle chat message in the destination server
        if self.url in destination_servers:
            logging.info(f"{self.url} receives chat as the destination server")

            for client_websocket in self.clients:
                await self.send_response(client_websocket, message)

        else:
            # forward the message to destination servers
            for server_url in destination_servers:
                websocket = self.neighbourhood.find_active_server(server_url)
                if websocket is None:
                    logging.error(
                        f"{self.url} cannot find destination server {server_url}"
                    )
                    continue

                logging.info(f"{self.url} forwards private chat to {server_url}")
                await self.neighbourhood.send_request(websocket, message)

    async def receive_hello(self, websocket, message):
        """Save client's public key and send client update to other servers"""
        client_public_key = message["public_key"]
        logging.info(f"{self.url} receives hello from client")
        self.clients[websocket] = {
            "public_key": client_public_key,
        }
        await self.send_client_update()

    # receive public chats and braodcast to connected clients and other neighbourhoods if valid message
    async def receive_public_chat(self, websocket, request):
        logging.info(f"{self.url} received public chat message")

        fingerprint = request["data"].get("sender", None)
        message = request["data"].get("message", None)
        counter = request.get("counter", None)
        if counter is None or fingerprint is None or message is None:
            logging.error(f"{self.url} received an invalid public_chat message")
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
        logging.info(f"{self.url} sends client list")

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
            logging.info(f"{self.url} sends client update to all servers")
            await self.neighbourhood.broadcast_request(response)
        else:
            neighbour_url = self.neighbour_websockets[websocket]
            logging.info(f"{self.url} sends client update to {neighbour_url}")
            await self.send_response(websocket, response)

    async def request_client_update(self):
        """
        (Between servers) Send request client update to all servers.
        Expect to receive an updated client list for each server.
        """
        logging.info(f"{self.url} requests client update from all servers")

        request = {
            "type": "client_update_request",
        }
        responses = await self.neighbourhood.broadcast_request(request, True)

        # Receive client_update response from other servers
        for websocket, message in responses.items():
            self.receive_client_update(websocket, message)

    def receive_client_update(self, websocket, message):
        clients = message["clients"]
        if websocket in self.neighbour_websockets:
            neighbour_url = self.neighbour_websockets[websocket]
        elif websocket in self.neighbourhood.active_servers:
            neighbour_url = self.neighbourhood.active_servers[websocket]
        else:
            logging.error(f"{self.url} receives client_update from invalid websocket")
            return

        logging.info(f"{self.url} receives client update from {neighbour_url}")
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
        logging.info(f"HTTP server running on port: {str(http_port)}")

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
            unique_filename = f"{os.path.splitext(filename)[0]}-{unique_id}{file_extension}"  # Append UUID to filename
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

            logging.info(f"File {filename} saved at {file_path}")

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


if __name__ == "__main__":
    # Arguments: server_url num_neighbours neighbour1_url neighbour2_url ...
    # Example: localhost:8080 2 localhost:8081 localhost:8081
    server_url = sys.argv[1]
    num_neighbours = int(sys.argv[2])
    neighbours = []
    for i in range(num_neighbours):
        neighbours.append(sys.argv[3 + i])

    # Start server
    server = Server(server_url)

    loop = asyncio.get_event_loop()
    for neighbour in neighbours:
        print(neighbour)
        loop.run_until_complete(server.add_neighbour_server(neighbour, "1"))

    try:
        loop.run_until_complete(server.start())
    except:
        loop.run_until_complete(server.stop())
    finally:
        loop.close()
