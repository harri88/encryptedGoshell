# encryptedGoshell
Reverse TCP shell with network level encryption (AES cipher) written in Golang.

- Installing packages for build

  go get github.com/gonutz/w32

  go get github.com/fatih/color

- Building the client/server
  
  set GOARCH=386
  
  go build server.go
  
  go build shell.go
