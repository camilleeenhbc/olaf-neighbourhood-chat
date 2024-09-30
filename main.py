import sys
import asyncio
import logging
import crypto
from client import Client

# logging.basicConfig(level=logging.ERROR)
# logging.disable()


async def prompt_input(prompt=""):
    return await asyncio.to_thread(input, prompt)


async def get_client_inputs(client: Client):
    print("INSTRUCTION")
    print("q: Quit")
    print("users: Retrieve list of online users")
    print("chat: Chat with a person")
    print("public: Chat with the public")
    print("upload: Upload file")
    print("download: Download file")
    print("\n\n")

    choice = await prompt_input()
    while choice != "q":
        if choice == "users":
            await handle_online_users(client)
        elif choice == "chat":
            await handle_chat(client)
        elif choice == "public":
            await handle_public_chat(client)
        elif choice == "upload":
            await handle_upload_file(client)
        elif choice == "download":
            await handle_download_file(client)

        choice = await prompt_input()

    await client.disconnect()


async def handle_online_users(client: Client):
    await client.request_client_list()


async def handle_chat(client: Client):
    num_participants = await prompt_input("Number of participants (exclude you): ")
    try:
        num_participants = int(num_participants)
    except Exception:
        print("Error: invalid input")
        return

    if num_participants <= 0:
        print("Error: invalid input")
        return

    # Choose chat participants
    public_keys = []
    fingerprints = [client.fingerprint]
    for i in range(num_participants):
        recipient = await prompt_input(f"Participant #{i+1}: ")

        try:
            _, address = recipient.split("@")
        except Exception:
            print("Error: invalid recipient")
            return

        public_key = client.get_public_key_from_username(recipient)
        if public_key is None:
            print("Error: Cannot found this client")
            return

        recipient_fingerprint = crypto.generate_fingerprint(public_key)

        public_keys.append(public_key)
        fingerprints.append(recipient_fingerprint)

    # Compose message
    message = await prompt_input("Message: ")

    # Chat
    await client.send_message(
        client.websocket,
        message,
        chat_type="chat",
        destination_servers=[address],
        recipient_public_keys=public_keys,
        participants=fingerprints,
    )


async def handle_public_chat(client: Client):
    # Compose message
    message = await prompt_input("Compose message for public chat: ")

    # Send public chat
    await client.send_message(
        client.websocket,
        message,
        chat_type="public_chat",
    )


# Handle file upload
async def handle_upload_file(client: Client):
    file_path = await prompt_input("Please enter file path: ")
    await client.upload_file(file_path)


# Handle file download
async def handle_download_file(client: Client):
    file_path = await prompt_input("Please enter file name: ")
    await client.download_file(file_path)


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
