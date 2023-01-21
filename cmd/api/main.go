package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/dvher/nibbin.cl_back/internal/database"
	"github.com/dvher/nibbin.cl_back/internal/server"
	_ "github.com/joho/godotenv/autoload"
)

func main() {

	port := flag.String("port", ":8080", "port to listen on")
	flag.Parse()

	router := server.New()

	db := database.Connect()

	log.Fatal(router.Run(*port))

	err := db.Close()

	if err != nil {
		fmt.Println(err)
	}

}
