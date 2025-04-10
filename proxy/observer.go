package proxy

import (
	"sync"
)

type Observer func(protocol string, dialer DialContextFunc)

var (
	observerMu sync.Mutex
	observers  []Observer
)

func AttachObserver(sub Observer) {
	observerMu.Lock()
	defer observerMu.Unlock()
	observers = append(observers, sub)
}

func ClearObservers() {
	observerMu.Lock()
	defer observerMu.Unlock()
	observers = nil
}

func NotifyObserversWithDialer(protocol string, dialer DialContextFunc) {
	observerMu.Lock()
	defer observerMu.Unlock()
	for _, fn := range observers {
		fn(protocol, dialer)
	}
}
