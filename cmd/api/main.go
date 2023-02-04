package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dvher/nibbin.cl_back/internal/database"
	"github.com/dvher/nibbin.cl_back/internal/server"
	_ "github.com/joho/godotenv/autoload"
)

func main() {

	port := flag.String("port", ":8080", "port to listen on")
	flag.Parse()

	sig := make(chan os.Signal, 1)

	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	router := server.New()

	go func() {
		<-sig
		err := database.DB.Close()

		if err != nil {
			log.Println(err)
		}

		os.Exit(1)
	}()

	log.Fatal(router.Run(*port))

}
