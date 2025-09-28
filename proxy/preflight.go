package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

type PreflightAction string

const (
	PreflightContinue PreflightAction = "continue"
	PreflightReject   PreflightAction = "reject"
	PreflightRedirect PreflightAction = "redirect"
	PreflightDirect   PreflightAction = "direct"
)

type Preflight struct {
	Proxy    ProxyConfig
	Endpoint string
}

type PreflightResult struct {
	Action   PreflightAction `json:"action"`
	Proxy    string          `json:"proxy,omitempty"`
	Endpoint string          `json:"endpoint,omitempty"`
	Message  string          `json:"msg,omitempty"`
	ExpireAt int64           `json:"expr,omitempty"`
}

func (pr *PreflightResult) Clone() *PreflightResult {
	npr := new(PreflightResult)
	*npr = *pr
	return npr
}

var preflightCli = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
	},
}

func addPreflight(auth ProxyConfig, dialer DialContextFunc, mws ...PreflightResultFetcherMW) DialContextFunc {
	cache := makeCache(auth)
	getPR := DoPreflight
	for _, mw := range mws {
		getPR = mw(getPR)
	}
	var directDialer net.Dialer
	return func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
		var result *PreflightResult
		var cachedStr string
		if val, ok := cache.Load(addr); ok {
			result = val
			cachedStr = "(cached)"
		} else if result, err = getPR(ctx, auth, addr); err != nil {
			return
		} else {
			cache.Store(addr, result)
		}
		switch result.Action {
		case PreflightDirect:
			realAddr := shuffleAddr(replaceEnvVar(result.Endpoint))
			log(ctx, "connect %s direct by %s(pick %s), msg: %s %s", addr, result.Endpoint, realAddr, result.Message, cachedStr)
			conn, err = directDialer.DialContext(ctx, network, realAddr)
		case PreflightRedirect:
			log(ctx, "connect %s redirect proxy to %s addr %s, msg: %s %s", addr, result.Proxy, FirstNonEmptyStr(result.Endpoint, addr), result.Message, cachedStr)
			dialer0, err := _loadGlobalDialer(result.Proxy, mws...)
			if err == nil {
				conn, err = dialer0(ctx, network, FirstNonEmptyStr(result.Endpoint, addr))
			}
		case PreflightReject:
			log(ctx, "connect %s is rejected, msg: %s %s", addr, result.Message, cachedStr)
			err = fmt.Errorf("forbid to connect to %s for %s", addr, result.Message)
		default:
			/* continue by default */
			conn, err = dialer(ctx, network, addr)
		}
		if err != nil {
			cache.Remove(addr)
		}
		return
	}
}

func DoPreflight(ctx context.Context, auth ProxyConfig, endpoint string) (result *PreflightResult, err error) {
	if auth.Location == "" {
		auth.Location = DefaultLocation()
	}
	if strings.Contains(auth.Address, ",") {
		for _, addr := range strings.Split(auth.Address, ",") {
			if result, err = doPreflight(ctx, auth.Type, addr, auth, endpoint); err == nil {
				return result, nil
			}
		}
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("fail to do preflight with %s", JSONStr(auth))
	}
	return doPreflight(ctx, auth.Type, auth.Address, auth, endpoint)
}

func doPreflight(ctx context.Context, addrType, addr string, auth ProxyConfig, endpoint string) (*PreflightResult, error) {
	addr, err := GetAddressResolver(addrType)(addr)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("http://%s/preflight", addr)
	req := &Preflight{
		Proxy:    auth,
		Endpoint: endpoint,
	}
	payload := JSONStr(req)
	requestReader := bytes.NewBufferString(payload)
	httpReq, err := http.NewRequest("POST", url, requestReader)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if val := ctx.Value(proxyTraceIdKey); val != nil {
		if preflightId, ok := val.(string); ok && preflightId != "" {
			httpReq.Header.Set("PreflightId", preflightId)
		}
	}
	resp, err := preflightCli.Do(httpReq)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		log(ctx, "preflight request %s fail %v", url, err)
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log(ctx, "preflight read response %s fail %v", url, err)
		return nil, err
	}
	respObj := struct {
		Code int             `json:"code"`
		Err  string          `json:"error"`
		Data json.RawMessage `json:"data"`
	}{}
	if err = json.Unmarshal(body, &respObj); err != nil {
		log(ctx, "preflight parse response of %s %s fail %v", url, string(body), err)
		return nil, err
	}
	if respObj.Code != 0 {
		log(ctx, "preflight response %s fail %v", url, respObj.Err)
		return nil, errors.New(respObj.Err)
	}
	var result PreflightResult
	if err = json.Unmarshal(respObj.Data, &result); err != nil {
		log(ctx, "preflight request %s fail %s", url, string(respObj.Data))
		return nil, errors.New(string(respObj.Data))
	}
	return &result, nil
}

func replaceEnvVar(naddr string) string {
	var arr []string
	if strings.Count(naddr, ":") == 1 {
		arr = strings.SplitN(naddr, ":", 2)
	} else {
		arr = []string{naddr}
	}
	for i, elem := range arr {
		if strings.HasPrefix(elem, "$") {
			if rv := os.Getenv(strings.TrimPrefix(elem, "$")); rv != "" {
				arr[i] = rv
			}
		}
	}
	naddr = strings.Join(arr, ":")
	return naddr
}

type PreflightResultFetcher func(context.Context, ProxyConfig, string) (*PreflightResult, error)

type PreflightResultFetcherMW func(PreflightResultFetcher) PreflightResultFetcher

func WithSeeds(seeds []string) PreflightResultFetcherMW {
	return func(next PreflightResultFetcher) PreflightResultFetcher {
		if len(seeds) == 0 {
			return next
		}
		set := make(map[string]struct{})
		for _, item := range seeds {
			set[item] = struct{}{}
		}
		var idx int64
		takeOne := func() string {
			return seeds[int(atomic.AddInt64(&idx, 1))%len(seeds)]
		}
		isSeed := func(addr string) bool {
			_, ok := set[addr]
			return ok
		}
		return func(ctx context.Context, auth ProxyConfig, addr string) (*PreflightResult, error) {
			if isSeed(addr) {
				return next(ctx, auth, addr)
			}
			seed := takeOne()
			log(ctx, "use seed %s do preflight instead of %s", seed, addr)
			pr, err := next(ctx, auth, seed)
			if err != nil {
				return nil, err
			}
			pr = pr.Clone()
			pr.Endpoint = addr
			return pr, nil
		}
	}
}

func WithRetry(times ...int) PreflightResultFetcherMW {
	count := 1
	if len(times) > 0 {
		count += times[0]
	}
	return func(next PreflightResultFetcher) PreflightResultFetcher {
		return func(ctx context.Context, auth ProxyConfig, addr string) (ret *PreflightResult, err error) {
			for i := 0; i < count; i++ {
				if ret, err = next(ctx, auth, addr); err != nil && strings.Contains(err.Error(), "EOF") {
					time.Sleep(time.Millisecond * 10)
					continue
				}
				break
			}
			return
		}
	}
}
