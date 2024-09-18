import asyncio
from typing import List
from server import Server

# server1 = Server("localhost", 9000)
# server2 = Server("localhost", 9001)
# server3 = Server("localhost", 9002)

servers: List[Server] = []
server_urls = ["localhost:9000", "localhost:9001", "localhost:9002"]

for url in server_urls:
    hostname, port = url.split(":")
    server = Server(hostname, port)

    # Remove current url from neighbours
    neighbours = server_urls.copy()
    neighbours.remove(url)
    server.add_servers(neighbours)

    servers.append(server)


loop = asyncio.get_event_loop()
for server in servers:
    loop.create_task(server.start())


async def send_message(server: Server, message):
    await asyncio.sleep(1)
    await server.neighbourhood.broadcast_message(message)


loop.create_task(send_message(servers[0], {"type": "random"}))

loop.run_forever()
