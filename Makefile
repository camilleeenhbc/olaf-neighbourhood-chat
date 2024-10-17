# Group 25
# - Hoang Bao Chau Nguyen - a1874801
# - Thi Tu Linh Nguyen - a1835497
# - Joanne Xue Ping Su - a1875646
# - Brooke Egret Luxi Wang - a1828458


server:
	python neighbourhood.py --start --urls localhost:8080 localhost:8081

client1:
	python main.py -d --url localhost:8080

client2:
	python main.py -d --url localhost:8081

test:
	pytest src/test/*

