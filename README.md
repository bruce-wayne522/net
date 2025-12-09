# Go Net Proxy

A powerful and extensible Go proxy library that supports SOCKS5 and HTTP proxies, providing advanced features like load balancing, proxy chaining, and TLS encryption.

## Features

*   **Multi-protocol Support:** Supports SOCKS5 and HTTP proxy protocols.
*   **Flexible Configuration:** Uses a URL-like string for proxy configuration, which is easy to parse and extend.
*   **Load Balancing:** Supports round-robin scheduling among multiple proxy servers to improve availability and performance.
*   **Proxy Chaining:** Allows linking multiple proxies together to form a chain.
*   **TLS Encryption:** Supports encrypted connections to the proxy server via TLS.
*   **Custom Authentication:** Provides an extensible authentication mechanism.
*   **Dynamic Configuration:** Supports reading and parsing proxy configurations from environment variables.
*   **Preflight Checks:** Can perform preflight checks to select the best proxy server before establishing a connection.

## Installation

```bash
go get github.com/bruce-wayne522/net/proxy
```

## Usage

Here is a basic example of how to use the `proxy` package to create a `Dialer`:

```go
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/bruce-wayne522/net/proxy"
)

func main() {
	// Create a proxy dialer
	dialer, err := proxy.BuildProxyDialer("socks5://user:password@127.0.0.1:1080")
	if err != nil {
		panic(err)
	}

	// Create an http.Client using the proxy dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: tr}

	// Send a request
	resp, err := client.Get("https://www.google.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
```

## Configuration

The proxy configuration is defined by a URL-like string with the following format:

```
scheme://[user:password@]host1:port1,host2:port2[?query]
```

*   **scheme:** The proxy protocol, which can be `socks5` or `http`.
*   **user:password@:** (optional) Authentication credentials.
*   **host1:port1,host2:port2:** A comma-separated list of proxy server addresses for load balancing.
*   **query:** (optional) Additional parameters, for example:
    *   `tls=true`: Enable TLS encryption.
    *   `tls_verify=true`: Verify the TLS certificate.
    *   `timeout=5`: Connection timeout in seconds.
    *   `preflight=true`: Enable preflight checks.
    *   `channel=my_channel`: Specify a channel name.
    *   `relay=tcp://...`: Specify a relay proxy.

### Examples

*   **Single SOCKS5 proxy:**
    ```
    socks5://127.0.0.1:1080
    ```

*   **SOCKS5 proxy with authentication:**
    ```
    socks5://user:password@127.0.0.1:1080
    ```

*   **Load-balanced HTTP proxies with TLS enabled:**
    ```
    http://proxy1.com:8080,proxy2.com:8080?tls=true
    ```

*   **Proxy Chaining (via environment variable):**
    You can set the `DEFAULT_PROXY` environment variable to create a proxy chain. For example, use `socks5://127.0.0.1:1080` as the default proxy and then connect through another `http` proxy.

    ```bash
    export DEFAULT_PROXY="socks5://127.0.0.1:1080"
    ```

    ```go
    dialer, err := proxy.BuildProxyDialer("http://user:pass@remote-proxy.com:8888")
    // ...
    ```

## Contributing

Contributions to this project are welcome via pull requests.

## License

This project is licensed under the [BSD-style license](LICENSE).
