package proxy

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

type PreflightCacheLevel int

const (
	PreflightCahceGlobal PreflightCacheLevel = iota
	PreflightCacheInstance
	PreflightCacheNone
)

func GetPreflightCache() PreflightCacheLevel {
	return plevel
}

func SetPreflightCache(l PreflightCacheLevel) {
	plevel = l
}

type pCache interface {
	Load(addr string) (*PreflightResult, bool)
	Remove(addr string)
	Store(addr string, result *PreflightResult)
}

var (
	/* preflight global cache */
	globalPreflightCache = new(sync.Map)
	globalDialerCache    = new(sync.Map)
	plevel               = PreflightCahceGlobal
)

func makeCache(auth ProxyConfig) pCache {
	if plevel == PreflightCacheNone {
		return nocache{}
	}
	c := &pcache{c: globalDialerCache, authStr: JSONStr(auth)}
	if plevel == PreflightCacheInstance {
		c.c = new(sync.Map)
	}
	return c
}

type pcache struct {
	authStr string
	c       *sync.Map
}

func (p *pcache) key(addr string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(p.authStr+":"+addr)))
}

func (p *pcache) Load(addr string) (*PreflightResult, bool) {
	key := p.key(addr)
	if val, ok := p.c.Load(key); ok {
		result := val.(*PreflightResult)
		if result.ExpireAt == 0 || time.Now().Unix() < result.ExpireAt {
			return result, true
		}
	}
	return nil, false
}

func (p *pcache) Remove(addr string) {
	key := p.key(addr)
	p.c.Delete(key)
}

func (p *pcache) Store(addr string, result *PreflightResult) {
	key := p.key(addr)
	p.c.Store(key, result)
}

func _loadGlobalDialer(url string, mws ...PreflightResultFetcherMW) (DialContextFunc, error) {
	if val, ok := globalDialerCache.Load(url); ok {
		return val.(DialContextFunc), nil
	}
	dialer, err := BuildProxyDialerByURL(url, mws...)
	if err != nil {
		return nil, err
	}
	globalDialerCache.Store(url, dialer)
	return dialer, nil
}

type nocache struct{}

func (nocache) Load(addr string) (*PreflightResult, bool)  { return nil, false }
func (nocache) Remove(addr string)                         {}
func (nocache) Store(addr string, result *PreflightResult) {}
