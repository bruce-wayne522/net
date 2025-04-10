package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// /path?k1=v1&k2=v2
type Location string

func (loc Location) Path() string {
	if i := strings.Index(string(loc), "?"); i >= 0 {
		return string(loc)[:i]
	}
	return string(loc)
}

func (loc Location) Params() url.Values {
	if i := strings.Index(string(loc), "?"); i >= 0 {
		val, _ := url.ParseQuery(string(loc)[i+1:])
		return val
	}
	return url.Values{}
}

func (loc Location) SetParam(k, v string) Location {
	vals := loc.Params()
	vals.Set(k, v)
	return Location(fmt.Sprintf("%v?%v", loc.Path(), vals.Encode()))
}

func (loc Location) IsUnknown() bool {
	return loc.Path() == "/unknown" || !strings.HasPrefix(string(loc), "/")
}

type LocationDecl struct {
	Name       string
	Attributes map[string]string
}

func (decl *LocationDecl) Set(key, val string) *LocationDecl {
	if decl.Attributes == nil {
		decl.Attributes = make(map[string]string)
	}
	decl.Attributes[key] = val
	return decl
}

type LocationCollector func() LocationDecl

var locationCollector LocationCollector

func SetLocationCollector(c LocationCollector) { locationCollector = c }

func DefaultLocation() Location {
	if locationCollector == nil {
		panic("no location collector found")
	}
	decl := locationCollector()
	if decl.Name == "" {
		decl.Name = "unknown"
	}
	params := url.Values{}
	for k, v := range decl.Attributes {
		if k != "" && v != "" {
			params.Set(k, v)
		}
	}
	if len(params) > 0 {
		return Location(fmt.Sprintf("/%s?%s", decl.Name, params.Encode()))
	}
	return Location(fmt.Sprintf("/%s", decl.Name))
}
