set GOOS=linux
set GOARCH=amd64
go build -o socks5g-linux-amd64
set GOOS=windows
go build -o socks5g-windows-amd64