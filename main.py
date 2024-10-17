"""An application that runs the client through I/O inputs

*****
Group 25
- Hoang Bao Chau Nguyen - a1874801
- Thi Tu Linh Nguyen - a1835497
- Joanne Xue Ping Su - a1875646
- Brooke Egret Luxi Wang - a1828458
"""

import asyncio
import logging
from argparse import ArgumentParser

from src.client import Client
from src.utils import crypto


async def prompt_input(prompt=""):
    """Prompt input in a separate thread"""
    result = await asyncio.to_thread(input, f"{prompt}\n")
    return result.strip()


async def get_client_inputs(client: Client):
    """Prompt client inputs"""
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
    """Print the list of online users after requesting from the server"""
    await client.request_client_list()

    print("Online users:")
    for server, clients in client.online_users.items():
        for c in clients:
            fingerprint = c["fingerprint"]
            tag = "(you)" if fingerprint == client.fingerprint else ""
            print(f"- {tag} ({server}) {fingerprint}")

    print("\n")


async def handle_chat(client: Client):
    """Prompt input for recipients and message and send chat to those recipients"""
    await handle_online_users(client)
    num_participants = await prompt_input("Number of participants (excluding you): ")
    try:
        num_participants = int(num_participants)
    except ValueError:
        print("Error: Please enter a valid number.")
        return

    if num_participants <= 0:
        print("Error: Invalid number of participants.")
        return

    destination_servers, public_keys, fingerprints = [], [], [client.fingerprint]
    for i in range(num_participants):
        recipient = await prompt_input(f"Enter participant fingerprint #{i + 1}: ")
        address, public_key = client.get_public_key_from_fingerprint(recipient)

        if public_key is None:
            print("Error: Could not find this client.")
            return

        recipient_fingerprint = crypto.generate_fingerprint(public_key)
        public_keys.append(public_key)
        fingerprints.append(recipient_fingerprint)
        if address not in destination_servers:
            destination_servers.append(address)

    while True:
        choice = await prompt_input(
            "Press Enter to type a message, (f) for file, (x) to exit chat: "
        )
        if choice == "x":
            print("Exiting chat...")
            break
        elif choice == "f":
            file_path = await prompt_input("Enter the file path: ")
            file_url = await client.upload_file(file_path)
            if not file_url:
                continue
            message = f"Sent a file! Download here: {file_url}"
        else:
            message = await prompt_input("Enter your message: ")

        await client.send_message(
            client.websocket,
            message,
            chat_type="chat",
            destination_servers=destination_servers,
            recipient_public_keys=public_keys,
            participants=fingerprints,
        )
        print("Message sent successfully.")


async def handle_public_chat(client: Client):
    """Send public message to all users"""
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
    """Download a file from the input file URL"""
    file_url = await prompt_input("Enter the file URL: ")
    await client.download_file(file_url)


async def main(client: Client):
    """Maintain client's connection with server and prompt inputs"""
    await asyncio.wait(
        [
            asyncio.create_task(client.connect_to_server()),
            asyncio.create_task(get_client_inputs(client)),
        ]
    )


def run(server_url):
    """Run a client that connects to the specified server's URL and prompt I/O inputs"""
    client = Client(server_url)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main(client))
    except KeyboardInterrupt:
        loop.run_until_complete(client.disconnect())
    finally:
        loop.close()


parser = ArgumentParser()
parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
parser.add_argument("--url", type=str, help="Server URL")

args = parser.parse_args()

if args.debug:
    logging.basicConfig(format="%(levelname)s:\t%(message)s", level=logging.INFO)
else:
    logging.basicConfig(format="%(levelname)s:\t%(message)s", level=logging.WARNING)

run(args.url)
