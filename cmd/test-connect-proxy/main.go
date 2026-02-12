// test-connect-proxy is a minimal HTTP CONNECT proxy for testing httpx -proxy with -protocol http2.
// Run: go run ./cmd/test-connect-proxy [listen]
// Default listen: 127.0.0.1:31280
// Then: echo "https://example.com" | httpx -proxy http://127.0.0.1:31280 -protocol http2 -silent -json
package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	listen := "127.0.0.1:31280"
	if len(os.Args) > 1 {
		listen = os.Args[1]
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("CONNECT proxy listening on %s", listen)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("read request: %v", err)
		return
	}
	if req.Method != http.MethodConnect {
		log.Printf("not CONNECT: %s", req.Method)
		return
	}
	target := req.URL.Host
	if req.URL.Port() == "" {
		target = net.JoinHostPort(req.URL.Host, "443")
	}
	backend, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		resp := "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(resp))
		return
	}
	defer backend.Close()
	if _, err := io.Copy(conn, strings.NewReader("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	go io.Copy(backend, br)
	io.Copy(conn, backend)
}
