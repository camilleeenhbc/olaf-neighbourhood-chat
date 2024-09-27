import sys
import asyncio
import logging
from threading import Thread
from server import Server
from client import Client
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# logging.basicConfig(level=logging.ERROR)
# logging.disable()


async def get_client_inputs(client: Client):
    print("INSTRUCTION")
    print("q: Quit")
    print("chat: Chat with a person")
    print("\n\n")
    choice = input("Choice: ")
    while choice != "q":
        if choice == "chat":
            await handle_chat(client)
        choice = input("Choice: ")


async def handle_chat(client: Client):
    # Get client list
    response = await client.request_client_list()
    server_list = response["servers"]
    print("List of clients: ")

    client_list = {}
    for item in server_list:
        server_address, clients = item["address"], item["clients"]
        for i in range(len(clients)):
            client_list[server_address] = clients
            print(f"- {i}@{server_address}")

    # Choose chat participant
    target_chat = input("Choose participant: ")
    try:
        index, address = target_chat.split("@")
        index = int(index)
        public_key_str = client_list[address][index]
    except:
        print("Error: Cannot found this client")
        return

    public_key = serialization.load_pem_public_key(
        public_key_str.encode(), backend=default_backend()
    )

    # Compose message
    message = input(f"Compose message to {target_chat}: ")

    # Chat
    await client.send_message(
        client.websocket,
        message,
        chat_type="chat",
        destination_servers=[address],
        recipient_public_keys=[public_key],
    )


async def main():
    # Arguments: server_url
    server_url = sys.argv[1]

    # Client connects to server
    client = Client(server_url)
    await client.connect_to_server()

    await get_client_inputs(client)
    # await server.stop()


asyncio.run(main())
