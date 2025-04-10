package proxy

import (
	"fmt"
	"sync"
)

type ProxyAddressResolver func(string) (string, error)

var proxyAddrResolvers sync.Map

func RegisterAddressResolver(typeName string, resolver ProxyAddressResolver) {
	proxyAddrResolvers.Store(typeName, resolver)
}

func GetAddressResolver(name string) ProxyAddressResolver {
	if val, ok := proxyAddrResolvers.Load(name); ok {
		return val.(ProxyAddressResolver)
	}
	if name == "" {
		return func(addr string) (string, error) { return addr, nil }
	}
	return func(addr string) (string, error) {
		return "", fmt.Errorf("can't resolve proxy address=%s type=%s", addr, name)
	}
}
