import asyncio
import logging
import src.utils.crypto as crypto

from typing import Dict
from server import Server
from argparse import ArgumentParser


logger = logging.getLogger(__name__)


class Neighbourhood:
    def __init__(self) -> None:
        self.servers: Dict[str, Server] = {}
        self.server_threads = {}
        self.start_after_add = False

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

        print(f"Added {server_address}")

        if self.start_after_add:
            self.start_server(server_address)

    def start_server(self, server_address):
        server = self.servers.get(server_address, None)
        if server is None:
            print(f"Cannot find server {server_address} to start")
            return

        if server_address in self.server_threads:
            print(f"Server {server_address} has already started")
            return

        self.server_threads[server_address] = asyncio.create_task(server.start())

    async def stop_server(self, server_address):
        if server_address in self.servers:
            await self.servers[server_address].stop()

        if server_address in self.server_threads:
            await self.server_threads[server_address]

    async def stop_all(self):
        tasks = [
            asyncio.create_task(self.stop_server(address)) for address in self.servers
        ]
        await asyncio.gather(*tasks)


async def prompt_input(prompt=""):
    return await asyncio.to_thread(input, prompt)


async def get_input(neighbourhood: Neighbourhood):
    print("NEIGHBOURHOOD\n")

    print("INSTRUCTION")
    print("add <server address>: Add a server")
    if neighbourhood.start_after_add is False:
        print("start <server address>: Start a server")
    print("stop <server address>: Stop a server")
    print("q: Quit")
    print("\n\n")

    choice = await prompt_input()
    while choice != "q":
        await handle_input(neighbourhood, choice)
        choice = await prompt_input()

    await neighbourhood.stop_all()


async def handle_input(neighbourhood: Neighbourhood, input_result):
    try:
        command, server_address = input_result.split(" ")
    except Exception:
        print("Invalid command")
        return

    if command == "add":
        await neighbourhood.add_server(server_address)
    if command == "start":
        neighbourhood.start_server(server_address)
    elif command == "stop":
        neighbourhood.stop_server(server_address)
    else:
        print("Invalid command")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "--urls", nargs="+", help="Servers to be added to the neighbourhood"
    )
    parser.add_argument(
        "--start", action="store_true", help="Start servers when they are added"
    )
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    neighbourhood = Neighbourhood()
    if args.start:
        neighbourhood.start_after_add = True

    if args.urls:
        for url in args.urls:
            loop.run_until_complete(neighbourhood.add_server(url))

    try:
        loop.run_until_complete(get_input(neighbourhood))
    except Exception:
        loop.run_until_complete(neighbourhood.stop_all())
    finally:
        loop.close()
