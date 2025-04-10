package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

var multiAddrs = new(sync.Map)

func shuffleAddr(addr string) string {
	if strings.Contains(addr, ",") {
		arr := strings.Split(addr, ",")
		if val, ok := multiAddrs.Load(addr); ok {
			idx := atomic.AddInt64(val.(*int64), 1)
			addr = arr[idx%int64(len(arr))]
		} else {
			var idx int64
			multiAddrs.Store(addr, &idx)
			addr = arr[0]
		}
	}
	return addr
}

func JSONStr(obj interface{}) string {
	bytes, err := Marshal(obj)
	if err != nil {
		return fmt.Sprintf("<json-marshal fail:%v>", err)
	}
	return string(bytes)
}

func Marshal(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	ret := buffer.Bytes()
	// golang's encoder would always append a '\n', so we should drop it
	if len(ret) > 0 && ret[len(ret)-1] == '\n' {
		ret = ret[:len(ret)-1]
	}
	return ret, nil
}

func Sha256(bs []byte) string {
	hash := sha256.Sum256(bs)
	/* make it shorter */
	return Base58Encode(hash[:])
}

func FirstNonEmptyStr(s ...string) string {
	for _, p := range s {
		if !IsBlank(p) {
			return p
		}
	}
	return ""
}

func IsBlank(s string) bool {
	return strings.TrimSpace(s) == ""
}

func SetDefaultProxyEnv(envName string) {
	env_default_proxy = envName
}

func GetEnvDefaultProxyURL() string {
	if env_default_proxy != "" {
		return os.Getenv(env_default_proxy)
	}
	return ""
}
