# Pre requisites
There must exist a .env file in the root of the directory with the following variables:
* DB_USER: The user to connect to the database
* DB_PASS: The password to connect to the database
* DB_NAME: The name of the database
* DB_ADDR: The address of the database
* DB_PORT: The port of the database
* SMTP_USER: The user to connect to the SMTP server
* SMTP_PASS: The password to connect to the SMTP server
* SMTP_HOST: The host of the SMTP server
* SMTP_PORT: The port of the SMTP server
* ADMIN_EMAIL: The email of the admin
* SESSION_KEY: The key used to authenticate the session
* SESSION_ENC: The encryption key used to encrypt the session
* SECRET_PEPPER: The pepper used to hash the passwords

This project assumes that you're using a MySQL database. If you're using a different database, you'll have to change the code in the `internal/database` package.  
This project uses reflex to automatically restart the server when a file is changed. If you don't want to use reflex, you can use the `make run` command instead.  
In order to use reflex you'll need to install it. You can do so by running `go install github.com/cespare/reflex@latest`.