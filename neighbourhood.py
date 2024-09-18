from websockets import WebSocketClientProtocol


class Neighbourhood:
    def __init__(self) -> None:
        self.active_servers = {}

    def add_active_server(self, server_url: str, websocket: WebSocketClientProtocol):
        self.active_servers[server_url] = websocket

    def remove_active_server(self, server_url: str):
        self.active_servers.pop(server_url)

    def broadcast_message(self, message):
        pass

    def send_client_list(self):
        pass

    def send_client_update(self):
        pass
