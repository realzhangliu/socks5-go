# socks5-go
[![Build Status](https://travis-ci.com/realzhangliu/socks5-go.svg?branch=dev)](https://travis-ci.com/realzhangliu/socks5-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/realzhangliu/socks5-go)](https://goreportcard.com/report/github.com/realzhangliu/socks5-go)

Inspired by go-socks5,This package provides full functionality of [socks5 protocol](https://www.rfc-editor.org/rfc/pdfrfc/rfc1928.txt.pdf).

>The protocol described here is designed to provide a framework for client-server applications in both the TCP and UDP domains to conveniently and securely use the services of a network firewall.


Feature
=======
The package has the following features:
- [x] "No Auth" mode
- [x] User/Password authentication mode
- [x] Support for the **CONNECT** command
- [x] Support for the **BIND** command(require the client to accept connections from the server,like FTP etc.)
- [x] Support for the **UDP ASSOCIATE** command
- [ ] Unit tests
- [ ] Graceful configuration
- [ ] Easy to use

Example
=======