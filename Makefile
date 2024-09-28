server1:
	python server.py localhost:8080 2 localhost:8081 localhost:8082

server2:
	python server.py localhost:8081 2 localhost:8080 localhost:8082

client1:
	python main.py localhost:8080

client2:
	python main.py localhost:8081

