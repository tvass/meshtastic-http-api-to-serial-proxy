# Meshtastic Serial Proxy (Go Port)

This Go code was generated with Claude based on the original Python implementation. It compiles and works, but has not been thoroughly tested. Use with caution.

## Building

Build for ARM Linux (e.g., Raspberry Pi):

```bash
$ GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w" -o meshtastic-proxy main.go
$ scp meshtastic-proxy 192.168.0.164:
$ ssh 192.168.0.164
$ openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "CN=localhost"
$ ./meshtastic-proxy --serial-port /dev/ttyACM0 --port 8080 --cert server.crt --key server.key  --debug
```

The `-ldflags="-s -w"` flags strip debug information to reduce binary size.