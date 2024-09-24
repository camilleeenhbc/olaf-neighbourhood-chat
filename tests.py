import asyncio
from typing import List
from server import Server

servers: List[Server] = []
# server_urls = ["localhost:5000", "localhost:5001", "localhost:5002"]
server_urls = ["localhost:5000", "localhost:5001"]

for url in server_urls:
    hostname, port = url.split(":")
    server = Server(hostname, port)

    # Remove current url from neighbours
    neighbours = server_urls.copy()
    neighbours.remove(url)
    server.add_neighbour_servers(neighbours)

    servers.append(server)


async def main():
    # Start servers
    start_tasks = [asyncio.create_task(server.start()) for server in servers]

    # Server 0 broadcasts to all other servers
    await asyncio.sleep(2)
    print("Sleep\n\n")
    # await servers[0].neighbourhood.broadcast_message({"type": "client_list_request"})

    # # Stop server 1
    # await asyncio.sleep(2)
    # print("Sleep\n\n")
    # await servers[1].stop()

    # # Server 0 re broadcasts
    # await asyncio.sleep(2)
    # print("Sleep\n\n")
    # await servers[0].neighbourhood.broadcast_message({"type": "client_list_request"})

    # Stop all servers
    for server in servers:
        await server.stop()

    await asyncio.gather(*start_tasks)


asyncio.run(main())
