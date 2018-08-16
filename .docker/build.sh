GOOS=linux GOARCH=amd64 go build ../src/scytale/

docker build -t scytale:local .
