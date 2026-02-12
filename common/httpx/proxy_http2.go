package httpx

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	utls "github.com/refraction-networking/utls"
)

// dialTLSViaProxy establishes a TLS connection to addr via an HTTP CONNECT proxy.
// It dials the proxy, sends CONNECT addr, reads 200, then performs TLS handshake over the tunnel.
// Supports TLS impersonation (Chrome/Random) when options request it.
func dialTLSViaProxy(ctx context.Context, network, addr string, cfg *tls.Config, proxyURLStr string, dialer *fastdialer.Dialer, options *Options) (net.Conn, error) {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, fmt.Errorf("proxy url: %w", err)
	}
	proxyHost := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			proxyHost = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			proxyHost = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	}

	conn, err := dialer.Dial(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("proxy dial: %w", err)
	}

	// CONNECT request per RFC 7230
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + pass))
		connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy response: %w", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/") {
		conn.Close()
		return nil, fmt.Errorf("proxy invalid response: %s", strings.TrimSpace(statusLine))
	}
	code := ""
	if parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 2); len(parts) >= 2 {
		parts = strings.SplitN(parts[1], " ", 2)
		if len(parts) >= 1 {
			code = parts[0]
		}
	}
	if code != "200" {
		// discard rest of response
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(statusLine))
	}

	// consume rest of headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy headers: %w", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// any buffered data belongs to the proxy response body; we must not feed it to TLS.
	// CONNECT 200 typically has no body, so we wrap conn to skip any buffered bytes once.
	tunnelConn := &connAfterBuf{Conn: conn, br: br}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	if cfg == nil {
		cfg = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	}
	tlsCfg := cfg.Clone()
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}

	if options.TlsImpersonateChrome || options.TlsImpersonate {
		uCfg := &utls.Config{
			InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
			ServerName:         tlsCfg.ServerName,
			MinVersion:         tlsCfg.MinVersion,
			MaxVersion:         tlsCfg.MaxVersion,
			CipherSuites:       tlsCfg.CipherSuites,
		}
		clientHelloID := utls.HelloRandomized
		if options.TlsImpersonateChrome {
			clientHelloID = utls.HelloChrome_106_Shuffle
		}
		uconn := utls.UClient(tunnelConn, uCfg, clientHelloID)
		if err := uconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake via proxy: %w", err)
		}
		return uconn, nil
	}

	tlsConn := tls.Client(tunnelConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake via proxy: %w", err)
	}
	return tlsConn, nil
}

// connAfterBuf wraps a net.Conn and a bufio.Reader that may have buffered data.
// Read first drains the buffer, then reads from Conn.
type connAfterBuf struct {
	net.Conn
	br *bufio.Reader
}

func (c *connAfterBuf) Read(p []byte) (n int, err error) {
	if c.br != nil {
		n, err = c.br.Read(p)
		if err != io.EOF {
			return n, err
		}
		c.br = nil
	}
	return c.Conn.Read(p)
}
