import sys
import asyncio
from server import Server
from client import Client


async def main():
    # Arguments: server_port num_neighbours neighbour1_url neighbour2_url ...
    # Example: 8080 2 localhost:8081 localhost:8081
    server_port = int(sys.argv[1])
    num_neighbours = int(sys.argv[2])
    neighbours = []
    for i in range(num_neighbours):
        neighbours.append(sys.argv[3 + i])

    # Start server
    task = None
    try:
        server = Server(port=int(server_port))
        server.add_neighbour_servers(neighbours)
        task = asyncio.create_task(server.start())
    except:
        print(f"Server localhost:{server_port} exists")

    # Client connects to server
    client = Client(f"localhost:{server_port}")
    await client.connect_to_server()

    if task:
        await task


if __name__ == "__main__":
    asyncio.run(main())
