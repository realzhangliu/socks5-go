package main

import (
	"github.com/realzhangliu/socks5-go"
	"log"
)

func main() {
	//var config socks5.Config
	//Implement yourself  Config , default is provided.
	S5Server := socks5.NewSocks5Server(nil)
	log.Println(S5Server.Listen())
}
