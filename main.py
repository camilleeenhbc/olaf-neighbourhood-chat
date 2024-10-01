import sys
import asyncio
import logging
import src.utils.crypto as crypto
from client import Client

# logging.basicConfig(level=logging.ERROR)
# logging.disable()


async def prompt_input(prompt=""):
    return await asyncio.to_thread(input, prompt)


async def get_client_inputs(client: Client):
    print("\n--- MENU ---")
    print("1. View online users")
    print("2. Chat with a user")
    print("3. Send a public message")
    print("4. Download a file")
    print("q. Quit")
    print("\n")

    choice = await prompt_input()
    while choice != "q":
        if choice == "1":
            await handle_online_users(client)
        elif choice == "2":
            await handle_chat(client)
        elif choice == "3":
            await handle_public_chat(client)
        elif choice == "4":
            await handle_download_file(client)
        else:
            print("Invalid option. Please try again.")
        choice = await prompt_input()
    await client.disconnect()


async def handle_online_users(client: Client):
    await client.request_client_list()
    await client.client_list_event.wait()

    for clients in client.online_users.values():
        for public_key in clients:
            username = client.get_username_from_public_key(public_key)
            tag = "(you)" if public_key == client.public_key else ""
            print(f"- {username} {tag}")


async def handle_chat(client: Client):
    num_participants = await prompt_input("Number of participants (excluding you): ")
    try:
        num_participants = int(num_participants)
    except ValueError:
        print("Error: Please enter a valid number.")
        return

    if num_participants <= 0:
        print("Error: Invalid number of participants.")
        return

    public_keys, fingerprints = [], [client.fingerprint]
    for i in range(num_participants):
        recipient = await prompt_input(
            f"Enter participant #{i + 1} (e.g., user@address): "
        )

        try:
            _, address = recipient.split("@")
        except Exception:
            print("Error: invalid recipient")
            return
        public_key = client.get_public_key_from_username(recipient)

        if public_key is None:
            print("Error: Could not find this client.")
            return

        recipient_fingerprint = crypto.generate_fingerprint(public_key)
        public_keys.append(public_key)
        fingerprints.append(recipient_fingerprint)

    choice = await prompt_input("Send a message or file? (m/f): ")
    if choice == "f":
        file_path = await prompt_input("Enter the file path: ")
        file_url = await client.upload_file(file_path)
        if file_url:
            await client.send_message(
                client.websocket,
                f"Sent a file! Download here: {file_url}",
                chat_type="chat",
                destination_servers=[address],
                recipient_public_keys=public_keys,
                participants=fingerprints,
            )
    else:
        message = await prompt_input("Enter your message: ")
        await client.send_message(
            client.websocket,
            message,
            chat_type="chat",
            destination_servers=[address],
            recipient_public_keys=public_keys,
            participants=fingerprints,
        )
        print("Message sent successfully.")


async def handle_public_chat(client: Client):
    choice = await prompt_input("Send a public message or file? (m/f): ")
    if choice == "f":
        file_path = await prompt_input("Enter the file path: ")
        file_url = await client.upload_file(file_path)
        if file_url:
            await client.send_message(
                client.websocket,
                f"Shared a file! Download here: {file_url}",
                chat_type="public_chat",
            )
    else:
        message = await prompt_input("Enter your public message: ")
        await client.send_message(client.websocket, message, chat_type="public_chat")


async def handle_download_file(client: Client):
    file_url = await prompt_input("Enter the file URL: ")
    await client.download_file(file_url)


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
