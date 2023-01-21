package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/joho/godotenv/autoload"
)

func Connect() *sql.DB {
	DB_NAME := os.Getenv("DB_NAME")
	DB_USER := os.Getenv("DB_USER")
	DB_PASSWORD := os.Getenv("DB_PASS")
	DB_HOST := os.Getenv("DB_ADDR")
	DB_PORT := os.Getenv("DB_PORT")

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME))

	if err != nil {
		log.Fatal("Couldn't connect to database")
	}

	err = db.Ping()

	if err != nil {
		db.Close()
		log.Fatal("Couldn't ping database")
	}

	return db

}
