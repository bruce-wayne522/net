package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"net/http"
	"net/url"

	"bufio"
	"encoding/base64"

	"golang.org/x/net/proxy"
)

const XAllowedHeaders = "x-allowed-headers"

func httpProxy(auth *ProxyConfig, forward proxy.Dialer) (proxy.Dialer, error) {
	const authHeaderKey = "Proxy-Authorization"
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth.AuthUser+":"+auth.AuthPassword))
	dialer := new(net.Dialer).DialContext
	if forward != nil {
		if cd, ok := forward.(proxy.ContextDialer); ok {
			dialer = cd.DialContext
		} else {
			dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return forward.Dial(network, addr)
			}
		}
	}
	extraHeaders := make(map[string]string)
	if headers := auth.GetExtra(XAllowedHeaders); headers != "" {
		for _, k := range strings.Split(headers, ",") {
			if v := auth.GetExtra(k); k != "" && v != "" {
				extraHeaders[k] = v
			}
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
		for k, v := range extraHeaders {
			connectReq.Header.Set(k, v)
		}
		conn, err := dialer(ctx, "tcp", proxyServer)
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
			return nil, fmt.Errorf("[http-proxy] CONNECT response status=%s", resp.Status)
		}
		return conn, nil
	}), nil
}
