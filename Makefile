server:
	python neighbourhood.py --start --urls localhost:8080 localhost:8081

client1:
	python main.py -d --url localhost:8080

client2:
	python main.py -d --url localhost:8081

test:
	pytest src/test/*

