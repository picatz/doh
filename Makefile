test: go-build
	./doh query google.com --labels --no-limit

go-build:
	go build -o doh

docker-test: docker-build
	docker run --rm -it doh:latest query google.com --labels --no-limit

docker-build:
	docker build -t doh:latest .
