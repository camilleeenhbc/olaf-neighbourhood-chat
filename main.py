import sys
import asyncio
import logging
from client import Client
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# logging.basicConfig(level=logging.ERROR)
# logging.disable()


async def get_client_inputs(client: Client):
    print("INSTRUCTION")
    print("q: Quit")
    print("users: Retrieve list of online users")
    print("chat: Chat with a person")
    print("public: Chat with the public")
    print("\n\n")

    choice = await asyncio.to_thread(input)
    while choice != "q":
        if choice == "users":
            await handle_online_users(client)
        elif choice == "chat":
            await handle_chat(client)
        elif choice == "public":
            await handle_public_chat(client)

        choice = await asyncio.to_thread(input)

    await client.disconnect()


async def handle_online_users(client: Client):
    await client.request_client_list()


async def handle_chat(client: Client):
    # Choose chat participant
    target_chat = input("Choose participant: ")
    try:
        index, address = target_chat.split("@")
        index = int(index)
        public_key_str = client.online_users[address][index]
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


async def handle_public_chat(client: Client):
    # Compose message
    message = input("Compose message for public chat: ")

    # Send public chat
    await client.send_message(
        client.websocket,
        message,
        chat_type="public_chat",
    )


async def main(client: Client):
    await asyncio.wait(
        [
            asyncio.create_task(client.connect_to_server()),
            asyncio.create_task(get_client_inputs(client)),
        ]
    )


# Arguments: server_url
server_url = sys.argv[1]

# Client connects to server
client = Client(server_url)

loop = asyncio.get_event_loop()
try:
    loop.run_until_complete(main(client))
except:
    loop.run_until_complete(client.disconnect())
finally:
    loop.close()
