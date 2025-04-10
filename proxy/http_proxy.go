package proxy

import (
	"context"
	"fmt"
	"io"
	"net"

	"net/http"
	"net/url"

	"bufio"
	"encoding/base64"

	"golang.org/x/net/proxy"
)

func httpProxy(auth *ProxyConfig, forward proxy.Dialer) (proxy.Dialer, error) {
	const authHeaderKey = "Proxy-Authorization"
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth.AuthUser+":"+auth.AuthPassword))
	dialer := net.Dial
	if forward != nil {
		dialer = func(network, addr string) (net.Conn, error) {
			return forward.Dial(network, addr)
		}
	}
	proxyServer := auth.Address
	return DialContextFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		connectReq := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		connectReq.Header.Add(authHeaderKey, authHeader)
		conn, err := dialer("tcp", proxyServer)
		if err != nil {
			return nil, fmt.Errorf("[http-proxy] connect server fail %w", err)
		}
		if err = connectReq.Write(conn); err != nil {
			return nil, fmt.Errorf("[http-proxy] write CONNECT request fail %w", err)
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("[http-proxy] parse CONNECT fail %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("[http-proxy] read CONNECT response fail %w", err)
			}
			conn.Close()
			return nil, fmt.Errorf("[http-proxy] CONNECT response status=%v", resp.Status)
		}
		return conn, nil
	}), nil
}
