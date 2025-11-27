package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bruce-wayne522/net/proxy/socks"
	"golang.org/x/net/proxy"
)

const (
	Extra_tag_protocol = "protocol"
)

var env_default_proxy string

type ProxyConfig struct {
	Scheme string `form:"-"`
	/* proxyAddr format host:port,host2:port2 */
	Address string `form:"-"`
	/* socksv5 related */
	AuthUser       string `form:"auth_user"`
	AuthPassword   string `form:"auth_password"`
	ChannelAuth    bool   `form:"channel_auth"`
	ChannelRelay   string `form:"relay"`
	RelayForRemote bool   `form:"remote_relay"`
	Channel        string `form:"channel"`
	Type           string `form:"type"`
	/* tls related */
	EnableTLS            bool `form:"tls"`
	TLSVerifyCertificate bool `form:"tls_verify"`
	/* proxy conn related */
	ProxyConnTimeoutSec int64 `form:"timeout"`

	Preflight bool     `form:"preflight"`
	Location  Location `form:"location"`

	Extra map[string]string `form:"extra"`
}

func (self ProxyConfig) Encode() string {
	query := url.Values{}
	if self.AuthUser != "" {
		query.Set("auth_user", self.AuthUser)
	}
	if self.AuthPassword != "" {
		query.Set("auth_password", self.AuthPassword)
	}
	if self.ChannelAuth {
		query.Set("channel_auth", "true")
	}
	if self.ChannelRelay != "" {
		query.Set("relay", self.ChannelRelay)
	}
	if self.RelayForRemote {
		query.Set("remote_relay", "true")
	}
	if self.Channel != "" {
		query.Set("channel", self.Channel)
	}
	if self.Type != "" {
		query.Set("type", self.Type)
	}
	if self.EnableTLS {
		query.Set("tls", "true")
	}
	if self.TLSVerifyCertificate {
		query.Set("tls_verify", "true")
	}
	if self.ProxyConnTimeoutSec != 0 {
		query.Set("timeout", strconv.FormatInt(self.ProxyConnTimeoutSec, 10))
	}
	if self.Preflight {
		query.Set("preflight", "true")
	}
	if self.Location != "" {
		query.Set("location", string(self.Location))
	}
	for k, v := range self.Extra {
		if k != "" && v != "" {
			query.Set(k, v)
		}
	}

	scheme := `tcp`
	if self.Scheme != "" {
		scheme = self.Scheme
	}
	/* scheme://dddress?querys */
	var builder strings.Builder
	builder.WriteString(scheme)
	builder.WriteString("://")
	builder.WriteString(self.Address)
	builder.WriteString("?")
	builder.WriteString(query.Encode())
	return builder.String()
}

func (self *ProxyConfig) GetChannel() string {
	if !self.ChannelAuth {
		return ""
	}
	if self.Channel != "" {
		return self.Channel
	}
	return self.Scheme
}

func (self *ProxyConfig) Resolve() *ProxyConfig {
	real := new(ProxyConfig)
	*real = *self
	getEnv := func(v string) string {
		/* well, sometimes we need empty value */
		return os.Getenv(strings.TrimPrefix(v, "$"))
	}
	if strings.HasPrefix(real.Address, "$") {
		real.Address = getEnv(real.Address)
	}
	if strings.HasPrefix(real.AuthUser, "$") {
		real.AuthUser = getEnv(real.AuthUser)
	}
	if strings.HasPrefix(real.AuthPassword, "$") {
		real.AuthPassword = getEnv(real.AuthPassword)
	}
	if strings.HasPrefix(real.ChannelRelay, "$") {
		real.ChannelRelay = getEnv(real.ChannelRelay)
	}
	if len(real.Channel) > 1 && strings.HasPrefix(real.Channel, "$") {
		real.Channel = getEnv(real.Channel)
	}
	return real
}

func (self *ProxyConfig) split() (ret []*ProxyConfig) {
	for _, addr := range strings.Split(self.Address, ",") {
		if addr != "" {
			cp := new(ProxyConfig)
			*cp = *self
			cp.Address = addr
			ret = append(ret, cp)
		}
	}
	return
}

// example: tcp://host1:7788,host2:8899?auth_password=pwd&auth_user=user&timeout=20&tls=false&tls_verify=false
func Decode(proxyURL string) (ProxyConfig, error) {
	scheme := "tcp"
	/* standard url.Parse can't decode scheme with `_` */
	if i := strings.Index(proxyURL, "://"); i > 0 {
		scheme = proxyURL[:i]
		proxyURL = "tcp" + proxyURL[i:]
	}
	var address string
	if i := strings.Index(proxyURL, "?"); i > 0 {
		j := strings.Index(proxyURL, "://")
		address = proxyURL[j+3 : i]
		proxyURL = proxyURL[:j+3] + "nohost" + proxyURL[i:]
	}
	uri, err := url.Parse(proxyURL)
	if err != nil {
		return ProxyConfig{}, err
	}
	if address == "" {
		address = uri.Host
	}
	config := ProxyConfig{Extra: make(map[string]string)}

	query := uri.Query()
	for key := range query {
		if v := query.Get(key); v != "" {
			switch key {
			case "auth_user":
				config.AuthUser = v
			case "auth_password":
				config.AuthPassword = v
			case "channel_auth":
				config.ChannelAuth = v == "true"
			case "relay":
				config.ChannelRelay = v
			case "remote_relay":
				config.RelayForRemote = v == "true"
			case "channel":
				config.Channel = v
			case "type":
				config.Type = v
			case "tls":
				config.EnableTLS = v == "true"
			case "tls_verify":
				config.TLSVerifyCertificate = v == "true"
			case "timeout":
				timeout, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					return config, err
				}
				config.ProxyConnTimeoutSec = timeout
			case "preflight":
				config.Preflight = v == "true"
			case "location":
				config.Location = Location(v)
			default:
				config.Extra[key] = v
			}
		}
	}
	config.Scheme = scheme
	config.Address = address
	return config, nil
}

type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type DialerMW func(DialContextFunc) DialContextFunc

func (f DialContextFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

func (f DialContextFunc) Dial(network, addr string) (net.Conn, error) {
	return f.DialContext(context.TODO(), network, addr)
}

func (f DialContextFunc) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	if timeout == 0 {
		return f.Dial(network, address)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return f.DialContext(ctx, network, address)
}

func BuildProxyDialerByURL(url string, mws ...PreflightResultFetcherMW) (DialContextFunc, error) {
	auth, err := Decode(url)
	if err != nil {
		return nil, err
	}
	return BuildProxyDialer(&auth, mws...)
}

// proxyAddr format host:port,host2:port2
func BuildProxyDialer(auth *ProxyConfig, mws ...PreflightResultFetcherMW) (DialContextFunc, error) {
	if auth == nil || auth.Address == "" {
		return nil, errors.New(`no proxy address`)
	}
	/* replace environment variables */
	auth = auth.Resolve()
	authList := auth.split()
	var dialers []DialContextFunc
	for _, item := range authList {
		if fn, err := buildSingleProxyDialer(item, mws...); err != nil {
			return nil, err
		} else {
			dialers = append(dialers, fn)
		}
	}
	return TraceDialer(RoundRobinDialers(dialers...)), nil
}

func buildSingleProxyDialer(auth *ProxyConfig, mws ...PreflightResultFetcherMW) (DialContextFunc, error) {
	/* default proxy */
	if url := GetEnvDefaultProxyURL(); url != "" {
		if base, err := Decode(url); err == nil && base.Scheme != auth.Scheme {
			base.Channel = auth.GetChannel()
			base.ChannelRelay = auth.Encode()
			auth = &base
		}
	}

	/* socks v5 auth credentials */
	pauth := &Auth{
		User:           auth.AuthUser,
		Password:       auth.AuthPassword,
		Channel:        auth.GetChannel(),
		ChannelRelay:   auth.ChannelRelay,
		ChannelAuth:    auth.ChannelAuth,
		RelayForRemote: auth.RelayForRemote,
	}

	/* dialer */
	var forward proxy.Dialer
	if auth.EnableTLS {
		/* tls configurations */
		forward = &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: !auth.TLSVerifyCertificate}}
	} else {
		/* direct dialer */
		forward = proxy.Direct
	}

	/* proxy connection timeout */
	timeout := time.Second * 60
	if auth.ProxyConnTimeoutSec > 0 {
		timeout = time.Duration(auth.ProxyConnTimeoutSec) * time.Second
	}

	/* build proxy dialer */
	return _buildSingleProxyDialer(auth, pauth, forward, timeout, mws...)
}

func _buildSingleProxyDialer(auth *ProxyConfig, pauth *Auth, forward proxy.Dialer, timeout time.Duration, mws ...PreflightResultFetcherMW) (DialContextFunc, error) {
	var proxyDialer proxy.Dialer
	var err error
	if protocol := auth.GetProtocol(); protocol == "http" {
		proxyDialer, err = httpProxy(auth, withAddressResolver(auth.Type, forward))
	} else {
		proxyDialer, err = SOCKS5(`tcp`, auth.Address, pauth, withAddressResolver(auth.Type, forward))
	}
	if err != nil {
		return nil, err
	}
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if cd, ok := proxyDialer.(contextDialer); ok {
			ctx, cancel := context.WithTimeout(socks.InitContext(ctx, addr), timeout)
			defer cancel()
			conn, err0 := cd.DialContext(ctx, network, addr)
			if err0 != nil {
				return nil, err0
			}
			if sconn, ok := conn.(*socks.Conn); ok && socks.GetConnectionId(ctx) != 0 {
				sconn.SetId(socks.GetConnectionId(ctx))
			}
			return conn, nil
		}
		return proxyDialer.Dial(network, addr)
	}
	/* preflight */
	if auth.Preflight {
		dialer = addPreflight(*auth, dialer, mws...)
	}

	return dialer, nil
}

const proxyTraceIdKey = "$proxy-trace-id"

var nextTraceNum uint64

func TraceDialer(dialer DialContextFunc) DialContextFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if ctx.Value(proxyTraceIdKey) == nil {
			traceId := hostnameHash + strconv.FormatUint(atomic.AddUint64(&nextTraceNum, 1), 10)
			ctx = context.WithValue(ctx, proxyTraceIdKey, traceId)
			ctx = withTraceTag(context.WithValue(ctx, proxyTraceIdKey, traceId), "trace:"+traceId)
		}
		return dialer(ctx, network, addr)
	}
}

func RoundRobinDialers(dialers ...DialContextFunc) DialContextFunc {
	if len(dialers) == 1 {
		return dialers[0]
	}
	var delta uint64
	return func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
		offset := int((atomic.AddUint64(&delta, 1) - 1) % uint64(len(dialers)))
		for i := 0; i < len(dialers); i++ {
			fn := dialers[int((i+offset)%len(dialers))]
			if conn, err = fn(ctx, network, addr); err == nil {
				return
			}
		}
		return
	}
}

func withAddressResolver(addressType string, forward proxy.Dialer) proxy.Dialer {
	return &customDialer{d: forward, resolve: GetAddressResolver(addressType)}
}

type customDialer struct {
	resolve ProxyAddressResolver
	d       proxy.Dialer
}

func (self *customDialer) Dial(network, addr string) (net.Conn, error) {
	addr, err := self.resolve(addr)
	if err != nil {
		return nil, err
	}
	return self.d.Dial(network, addr)
}

func (self *customDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	addr, err := self.resolve(addr)
	if err != nil {
		return nil, err
	}
	if f, ok := self.d.(proxy.ContextDialer); ok {
		return f.DialContext(ctx, network, addr)
	}
	return self.d.Dial(network, addr)
}

func (self ProxyConfig) GetExtra(k string) string {
	if extra := self.Extra; extra != nil {
		return extra[k]
	}
	return ""
}

func (self ProxyConfig) GetProtocol() string {
	if protocol := self.GetExtra(Extra_tag_protocol); protocol != "" {
		return protocol
	}
	return self.Scheme
}
