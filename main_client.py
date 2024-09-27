import asyncio
import websockets
from server import Server
from client import Client
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


async def run_server():
    # Create a server instance
    server = Server()

    # Add neighboring servers if necessary (example: other servers in the network)
    server.add_neighbour_servers(["localhost:8081", "localhost:8082"])

    # Start the server
    await server.start()


async def run_client1():
    # Initialize Client1
    client1 = Client("localhost:80")

    # Connect Client1 to the server
    async with websockets.connect(f"ws://{client1.server_url}") as websocket:
        # Send hello message to introduce Client1
        await client1.send_message(websocket, chat_type="hello")

        # Export Client1's public key
        client1_public_key_pem = client1.export_public_key().decode()
        print(f"Client1's Public Key: {client1_public_key_pem}")

        return client1_public_key_pem


async def run_client2(client1_public_key_pem):
    client2 = Client("localhost:80")

    # Connect Client2 to the server
    async with websockets.connect(f"ws://{client2.server_url}") as websocket:
        await client2.send_message(websocket, chat_type="hello")

        # Load Client1's public key from PEM format
        client1_public_key = serialization.load_pem_public_key(
            client1_public_key_pem.encode(), backend=default_backend()
        )

        # Send a private chat message to Client1
        await client2.send_message(
            websocket,
            "Hello, Client1!",
            chat_type="chat",
            destination_servers=["server1.example.com"],
            recipient_public_keys=[client1_public_key],  # Encrypt for Client1
        )

        # Send a public chat message
        await client2.send_message(
            websocket,
            "Hello, everyone in public chat!",
            chat_type="public_chat",
        )


async def main():
    # Run the server in the background
    server_task = asyncio.create_task(run_server())

    # Simulate Client1 sending its public key
    async with websockets.connect(f"ws://localhost:80") as websocket:
        client1_public_key_pem = await run_client1()

        # Simulate Client2 receiving Client1's public key and sending messages
        await run_client2(client1_public_key_pem)

    # Wait for the server to finish (this is an infinite loop)
    await server_task


if __name__ == "__main__":
    asyncio.run(main())
