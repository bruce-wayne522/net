package proxy

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"testing"
)

func fixed_fields_of_proxy() map[string]int {
	f := make(map[string]int)
	typ := reflect.TypeOf(ProxyConfig{})
	for i := 0; i < typ.NumField(); i++ {
		if tag := typ.Field(i).Tag.Get(`form`); tag == "" || tag == "-" {
			continue
		}
		f[typ.Field(i).Tag.Get(`form`)] = i
	}
	return f
}

func Encode(self ProxyConfig) string {
	typ := reflect.TypeOf(self)
	val := reflect.ValueOf(self)
	proxyFixedFields := fixed_fields_of_proxy()

	query := url.Values{}
	for i := 0; i < typ.NumField(); i++ {
		if tag := typ.Field(i).Tag.Get(`form`); tag == "" || tag == "-" {
			continue
		}
		switch val.Field(i).Kind() {
		case reflect.Bool:
			if sval := val.Field(i).Bool(); sval {
				query.Add(typ.Field(i).Tag.Get(`form`), `true`)
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if sval := val.Field(i).Int(); sval != 0 {
				query.Add(typ.Field(i).Tag.Get(`form`), strconv.FormatInt(sval, 10))
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if sval := val.Field(i).Uint(); sval != 0 {
				query.Add(typ.Field(i).Tag.Get(`form`), strconv.FormatUint(sval, 10))
			}
		case reflect.String:
			if sval := val.Field(i).String(); sval != "" {
				query.Add(typ.Field(i).Tag.Get(`form`), sval)
			}
		case reflect.Map:
			if typ.Field(i).Tag.Get(`form`) == "extra" {
				if extra, ok := val.Field(i).Interface().(map[string]string); ok && extra != nil {
					for k, v := range extra {
						if _, isff := proxyFixedFields[k]; !isff {
							query.Set(k, v)
						}
					}
				}
			}
		default:
			sval := fmt.Sprint(val.Field(i).Interface())
			if sval != "" {
				query.Add(typ.Field(i).Tag.Get(`form`), sval)
			}
		}
	}
	scheme := `tcp`
	if self.Scheme != "" {
		scheme = self.Scheme
	}
	return fmt.Sprintf(`%s://%s?%s`, scheme, self.Address, query.Encode())
}

func TestEncode(t *testing.T) {
	config := ProxyConfig{
		Scheme:               "myscheme",
		Address:              "localhost:9527",
		AuthUser:             "user01",
		AuthPassword:         "pasword01",
		ChannelAuth:          true,
		ChannelRelay:         "/root/child",
		RelayForRemote:       true,
		Channel:              "channel1",
		Type:                 "type1",
		EnableTLS:            true,
		TLSVerifyCertificate: true,
		ProxyConnTimeoutSec:  100,
		Preflight:            true,
		Location:             Location("complex?a=b"),
		Extra: map[string]string{
			"e1": "v1",
			"e2": "v2",
		},
	}
	orig := config.Encode()
	if o2 := Encode(config); o2 != orig {
		t.Fatalf("%s\n%s", orig, o2)
	}
	p, err := Decode(orig)
	if err != nil {
		t.Fatal(err)
	}
	if newUrl := p.Encode(); newUrl != orig {
		t.Fatalf("%s\n%s", orig, newUrl)
	}
	if newUrl := Encode(p); newUrl != orig {
		t.Fatalf("%s\n%s", orig, newUrl)
	}
	t.Log("original", orig)
}

func TestHttpEncode(t *testing.T) {
	config := ProxyConfig{
		Scheme:              "http",
		Address:             "localhost:9527",
		ProxyConnTimeoutSec: 30,
		Extra: map[string]string{
			"x-allowed-headers":   "Proxy-Authorization",
			"Proxy-Authorization": "any-auth-string-here",
		},
	}
	orig := config.Encode()
	t.Log("original", orig)
	config = ProxyConfig{
		Scheme:              "http",
		Address:             "localhost:9527",
		AuthUser:            "any-user",
		AuthPassword:        "any-password",
		ProxyConnTimeoutSec: 30,
	}
	orig = config.Encode()
	t.Log("original", orig)
	if o2 := Encode(config); o2 != orig {
		t.Fatalf("%s\n%s", orig, o2)
	}
	p, err := Decode(orig)
	if err != nil {
		t.Fatal(err)
	}
	if newUrl := p.Encode(); newUrl != orig {
		t.Fatalf("%s\n%s", orig, newUrl)
	}
	if newUrl := Encode(p); newUrl != orig {
		t.Fatalf("%s\n%s", orig, newUrl)
	}
}
