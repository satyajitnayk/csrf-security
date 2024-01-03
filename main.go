package main

import (
	"log"

	"github.com/satyajitnayk/server"
)

var host = "localhost"
var port = "9000"

func main() {
	db.InitDB()

	jwtErr := myJwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initializing the JWT!")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Errorb starting the server!")
		log.Fatal(serverErr)
	}
}
