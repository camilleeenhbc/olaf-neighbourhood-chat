class Neighbourhood:
    def __init__(self) -> None:
        self.active_servers = []

    def add_active_server(self, server_url: str):
        self.active_servers.append(server_url)

    def remove_active_server(self, server_url: str):
        self.active_servers.remove(server_url)

    def broadcast_message(self, message):
        pass

    def send_client_list(self):
        pass

    def send_client_update(self):
        pass
