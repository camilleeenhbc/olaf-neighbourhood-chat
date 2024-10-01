import asyncio
import logging
import src.utils.crypto as crypto

from typing import Dict
from server import Server


logger = logging.getLogger(__name__)


class Neighbourhood:
    def __init__(self) -> None:
        self.servers: Dict[str, Server] = {}
        self.server_threads = {}

    async def add_server(self, server_address):
        if server_address in self.servers:
            print(f"Server {server_address} exists")
            return

        server = Server(server_address)
        self.servers[server_address] = server
        server_public_key = crypto.export_public_key(server.public_key)

        # All servers add the new neighbours
        for neighbour_address, neighbour in self.servers.items():
            if server_address != neighbour_address:
                neighbour_public_key = crypto.export_public_key(neighbour.public_key)
                await server.add_neighbour_server(
                    neighbour_address, neighbour_public_key
                )
                await neighbour.add_neighbour_server(server_address, server_public_key)

        print("Added")

    def start_server(self, server_address):
        server = self.servers.get(server_address, None)
        if server is None:
            print(f"Cannot find server {server_address} to start")
            return

        # self.server_threads[server_address] = asyncio.create_task(server.run())
        self.server_threads[server_address] = asyncio.create_task(server.start())

    def stop_server(self, server_address):
        self.servers[server_address].stop()


async def prompt_input(prompt=""):
    return await asyncio.to_thread(input, prompt)


async def get_input(neighbourhood: Neighbourhood):
    print("NEIGHBOURHOOD\n")

    print("INSTRUCTION")
    print("add <server address>: Add a server")
    print("start <server address>: Start a server")
    print("stop <server address>: Stop a server")
    print("q: Quit")
    print("\n\n")

    choice = await prompt_input()
    while choice != "q":
        await handle_input(neighbourhood, choice)
        choice = await prompt_input()

    for server_address in neighbourhood.servers:
        neighbourhood.stop_server(server_address)


async def handle_input(neighbourhood: Neighbourhood, input_result):
    try:
        command, server_address = input_result.split(" ")
    except Exception:
        print("Invalid command")
        return

    if command == "add":
        await neighbourhood.add_server(server_address)
    elif command == "start":
        neighbourhood.start_server(server_address)
    elif command == "stop":
        neighbourhood.stop_server(server_address)
    else:
        print("Invalid command")


if __name__ == "__main__":
    neighbourhood = Neighbourhood()
    asyncio.run(get_input(neighbourhood))
