package proxy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

type GDID string

type ProxyBuilder struct {
	GDID        GDID
	Gateway     string
	SetLocation Location
	Err         error
}

var (
	globalGDIDProxy sync.Map
	globalGDIDGw    string
)

func init() {
	LoadEnvGateway()
}

func LoadEnvGateway() {
	pc := &ProxyConfig{
		Scheme:       "anonymous-gw",
		Address:      os.Getenv("GATEWAY_ADDRESS"),
		AuthUser:     os.Getenv("GATEWAY_USER"),
		AuthPassword: os.Getenv("GATEWAY_PWD"),
		Type:         os.Getenv("GATEWAY_TYPE"),
		ChannelAuth:  true,
		ChannelRelay: "direct",
		Channel:      "tcp",
	}
	if pc.Address != "" && pc.AuthUser != "" && pc.AuthPassword != "" {
		SetGlobalGDIDGateway(pc.Encode())
	}
}

func GetGlobalGDIDGateway() string {
	return globalGDIDGw
}

func SetGlobalGDIDGateway(url string) {
	if url != "" {
		globalGDIDGw = url
	}
}

func (gdid GDID) ProxyProtocol() string {
	return Sha256([]byte(gdid))
}

func (gdid GDID) Dir() string {
	if tokens := gdid.Tokenize(); len(tokens) > 0 {
		return strings.Join(tokens[:len(tokens)-1], "/")
	}
	return ""
}

func (gdid GDID) Car() GDID {
	tokens := gdid.Tokenize()
	if len(tokens) > 0 {
		return GDID(tokens[0])
	}
	return GDID("")
}

func (gdid GDID) Cdr() GDID {
	tokens := gdid.Tokenize()
	if len(tokens) > 1 {
		return GDID(strings.Join(tokens[1:], ""))
	}
	return GDID("")
}

func (gdid GDID) Hash() string {
	return rawSha256([]byte(gdid))
}

func (gdid GDID) Tokenize() (ret []string) {
	arr := strings.Split(string(gdid), "/")
	for _, item := range arr {
		if item != "" && item != "/" {
			ret = append(ret, "/"+item)
		}
	}
	return
}

func (gdid GDID) ProxyBuilder() *ProxyBuilder {
	return &ProxyBuilder{GDID: gdid}
}

func (gdid GDID) WithGateway(gwurl string) *ProxyBuilder {
	return &ProxyBuilder{GDID: gdid, Gateway: gwurl}
}

func relativeTo(p1, p2 string) string {
	g1, g2 := GDID(p1), GDID(p2)
	t1, t2 := g1.Tokenize(), g2.Tokenize()
	var i int
	for ; i < len(t1) && i < len(t2); i++ {
		if t1[i] != t2[i] {
			break
		}
	}
	if i > 0 {
		t1 = t1[i:]
		t2 = t2[i:]
	}
	return strings.Join(t2, "")
}

func (dsp *ProxyBuilder) WithLocation(loc Location) *ProxyBuilder {
	dsp.SetLocation = loc
	return dsp
}

func (dsp *ProxyBuilder) GetProxy() (*ProxyConfig, error) {
	if dsp.Err != nil {
		return nil, dsp.Err
	}
	gw := dsp.Gateway
	if gw == "" {
		gw = globalGDIDGw
	}
	if gw == "" {
		return nil, errors.New("no gdid gateway found")
	}
	if strings.HasPrefix(gw, "$") {
		gw = os.Getenv(strings.TrimPrefix(gw, "$"))
	}
	pc, err := Decode(gw)
	if err != nil {
		return nil, err
	}
	loc := dsp.SetLocation
	if string(loc) == "" {
		loc = DefaultLocation()
	}
	relay := relativeTo(loc.Path(), dsp.GDID.Dir())
	/* set gw name & relay */
	pc.Scheme = dsp.GDID.ProxyProtocol()
	pc.ChannelRelay = relay
	pc.Preflight = true
	pc.Location = loc.SetParam("gdid", string(dsp.GDID))

	return &pc, nil
}

func (dsp *ProxyBuilder) GetDialer(mws ...PreflightResultFetcherMW) (DialContextFunc, error) {
	if dsp.Err != nil {
		return nil, dsp.Err
	}
	pc, err := dsp.GetProxy()
	if err != nil {
		return nil, err
	}
	return BuildProxyDialer(pc, mws...)
}

func (dsp *ProxyBuilder) EnableProxy(mws ...PreflightResultFetcherMW) *ProxyBuilder {
	pc, err := dsp.GetProxy()
	if err != nil {
		dsp.Err = err
		return dsp
	}
	key := pc.Encode()
	if _, ok := globalGDIDProxy.Load(key); ok {
		return dsp
	}
	if err = NotifyObservers(pc, mws...); err != nil {
		dsp.Err = err
		return dsp
	}
	globalGDIDProxy.Store(key, struct{}{})
	return dsp
}

func NotifyObservers(auth *ProxyConfig, mws ...PreflightResultFetcherMW) error {
	/* check protocol name */
	if auth.Scheme == "" {
		return fmt.Errorf(`bad protocal name %s`, auth.Scheme)
	}
	if auth.Address == "" {
		return fmt.Errorf(`bad address %s`, auth.Address)
	}

	dialFn, err := BuildProxyDialer(auth, mws...)
	if err != nil {
		return err
	}
	NotifyObserversWithDialer(auth.Scheme, dialFn)
	return nil
}

func NotifyObserversByURL(url string, mws ...PreflightResultFetcherMW) error {
	auth, err := Decode(url)
	if err != nil {
		return err
	}
	return NotifyObservers(&auth, mws...)
}
