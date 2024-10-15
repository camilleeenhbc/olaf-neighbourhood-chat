# olaf-s-biggest-fans-
OLAF Neighbourhood Protocol - Secure Programming

## Student Names and Numbers
- Hoang Bao Chau Nguyen - a1874801
- Thi Tu Linh Nguyen - a1835497
- Joanne Xue Ping Su - a1875646
- Brooke Egret Luxi Wang - a1828458

## List of Python dependencies
```
websockets==13.0.1
cryptography==43.0.1
black==24.8.0
aiohttp==3.10.7
```

## Set up

### Set up virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies
```bash
pip install -r requirements.txt
```

## Usage
### Servers
Run `neighbourhood.py` to share the public keys among servers and start the servers.

This script reads the command line arguments and I/O input to add new servers, start and stop servers.

For example, to start three servers `localhost:8080`, `localhost:8081`, and `localhost:8082`, use this following command.
```bash
python src/neighbourhood.py --start --urls localhost:8080 localhost:8081 localhost:8082
```

For more control, please use I/O inputs to execute the command. This following command is the I/O version of the command above.
```bash
python src/neighbourhood.py

# In I/O input
# Add servers to the neighbourhood - the servers share address and public key with each other
add localhost:8080
add localhost:8081
add localhost:8082
# Start the server websockets
start localhost:8080
start localhost:8081
start localhost:8082
```

You can skip typing `start <server address>` by adding the `--start` flag in the command line argument.

To stop the script, enter `q` to quit the program.

## Client
Use the following command to run the client (for example, to connect with the server at `localhost:8080`).
```bash
python src/main.py --url localhost:8080
```

Follow the I/O input instructions printed in the terminal to view online users, send chats, and download file.


