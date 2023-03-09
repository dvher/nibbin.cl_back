package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/joho/godotenv/autoload"
)

var DB *sql.DB

func init() {

	if DB == nil {
		connect()
		log.Println("Connected to database")
	}

}

func connect() {
	DB_NAME := os.Getenv("DB_NAME")
	DB_USER := os.Getenv("DB_USER")
	DB_PASS := os.Getenv("DB_PASS")
	DB_HOST := os.Getenv("DB_ADDR")
	DB_PORT := os.Getenv("DB_PORT")

	var err error

	DB, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME))

	if err != nil {
		log.Fatal("Couldn't connect to database", err)
	}

	err = DB.Ping()

	if err != nil {
		DB.Close()
		log.Fatal("Couldn't ping database", err)
	}

}
