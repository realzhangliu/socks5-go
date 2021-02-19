package main

import (
	"github.com/realzhangliu/socks5-go"
	"log"
	"net/http"
)

func main() {
	//pprof
	go func() {
		log.Println(http.ListenAndServe("localhost:8866", nil))
	}()
	S5Server := socks5.NewSocks5Server(nil)
	log.Println(S5Server.Listen())
}
