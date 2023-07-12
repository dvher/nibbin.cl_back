build:
	go build -o server cmd/api/main.go

run: build
	./server

watch:
	reflex -r '\.go$$' -s -- sh -c 'echo "\033[1;31mResetting...\033[0m"; $(MAKE) run'
