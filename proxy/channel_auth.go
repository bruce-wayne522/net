package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/bruce-wayne522/net/proxy/socks"
	"golang.org/x/net/proxy"
)

type Auth struct {
	User, Password string
	Channel        string
	ChannelRelay   string
	RelayForRemote bool
	ChannelAuth    bool
}

// SOCKS5 returns a Dialer that makes SOCKSv5 connections to the given
// address with an optional username and password.
// See RFC 1928 and RFC 1929.
func SOCKS5(network, address string, auth *Auth, forward proxy.Dialer) (proxy.Dialer, error) {
	d := socks.NewDialer(network, address)
	if forward != nil {
		if f, ok := forward.(proxy.ContextDialer); ok {
			d.ProxyDial = func(ctx context.Context, network string, address string) (net.Conn, error) {
				return f.DialContext(ctx, network, address)
			}
		} else {
			d.ProxyDial = func(ctx context.Context, network string, address string) (net.Conn, error) {
				return dialContext(ctx, forward, network, address)
			}
		}
	}
	if auth.ChannelAuth {
		cp := &channelAuth{channel: auth.Channel, channelRelay: auth.ChannelRelay, user: auth.User, password: auth.Password, relayForRemote: auth.RelayForRemote}
		d.AuthMethods = []socks.AuthMethod{
			socks.AuthMethodNotRequired,
			AuthMethodChannel,
		}
		d.Authenticate = cp.Authenticate
	} else if auth.User != "" && auth.Password != "" {
		up := &socks.UsernamePassword{
			Username: auth.User,
			Password: auth.Password,
		}
		cp := &channelAuth{next: up.Authenticate, channel: auth.Channel, channelRelay: auth.ChannelRelay, relayForRemote: auth.RelayForRemote}
		d.AuthMethods = []socks.AuthMethod{
			socks.AuthMethodNotRequired,
			socks.AuthMethodUsernamePassword,
			AuthMethodChannel,
		}
		d.Authenticate = cp.Authenticate
	}
	return d, nil
}

// WARNING: this can leak a goroutine for as long as the underlying Dialer implementation takes to timeout
// A Conn returned from a successful Dial after the context has been cancelled will be immediately closed.
func dialContext(ctx context.Context, d proxy.Dialer, network, address string) (net.Conn, error) {
	var (
		conn net.Conn
		done = make(chan struct{}, 1)
		err  error
	)
	go func() {
		conn, err = d.Dial(network, address)
		close(done)
		if conn != nil && ctx.Err() != nil {
			conn.Close()
		}
	}()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-done:
	}
	return conn, err
}

const AuthMethodChannel socks.AuthMethod = 100
const (
	ChannelAuthVersion  = uint8(1)
	ChannelAuthVersion2 = uint8(2)
	ChannelAuthVersion3 = uint8(3)
	AuthSuccess         = uint8(0)
	AuthFailure         = uint8(1)
)

type channelAuth struct {
	user, password string
	channel        string
	channelRelay   string
	relayForRemote bool
	next           func(context.Context, io.ReadWriter, socks.AuthMethod) error
}

func (self *channelAuth) Authenticate(ctx context.Context, rw io.ReadWriter, auth socks.AuthMethod) error {
	switch auth {
	case socks.AuthMethodNotRequired:
		return nil
	case AuthMethodChannel:
		version := self.useAuthVersion()
		b, err := self.basicInfoBytes()
		if err != nil {
			return err
		}

		credentials := []byte(fmt.Sprintf("%s:%s", self.user, self.password))
		b = append(b, int2uintx(len(credentials), 32)...)
		b = append(b, credentials...)

		if _, err := rw.Write(b); err != nil {
			return err
		}
		if _, err := io.ReadFull(rw, b[:2]); err != nil {
			return err
		}
		if b[0] != version {
			return errors.New("invalid channel version")
		}
		if b[1] != AuthSuccess {
			return errors.New("channel authentication failed")
		}

		bs := []byte{0, 0, 0, 0}
		if _, err := io.ReadFull(rw, bs); err != nil {
			return err
		}
		connId := binary.LittleEndian.Uint32(bs)
		socks.SetConnectionId(ctx, connId)
		log(ctx, "channel=%v,version=%v,connection=%v auth success", self.channel, version, connId)
		return nil
	}
	if self.next != nil {
		return self.next(ctx, rw, auth)
	}
	return errors.New("unsupported authentication method " + strconv.Itoa(int(auth)))
}

func (self *channelAuth) GetCode() uint8 { return uint8(AuthMethodChannel) }

func (self *channelAuth) useAuthVersion() uint8 {
	return ChannelAuthVersion3
}

func (self *channelAuth) basicInfoBytes() ([]byte, error) {
	if len(self.channel) > 128 {
		return nil, fmt.Errorf("socks channel %v to long", self.channel)
	} else if len(self.channel) == 0 {
		return nil, errors.New("socks channel is blank")
	}
	version := self.useAuthVersion()
	if size := len(self.channelRelay); size > 128 {
		if version >= ChannelAuthVersion2 && size <= 10240 {
		} else {
			return nil, fmt.Errorf("socks channel relay %v to long(%v)", self.channelRelay, size)
		}
	}
	b := []byte{version}
	switch version {
	case ChannelAuthVersion2:
		channelToken := self.channel
		if len(self.channelRelay) > 0 {
			channelToken = fmt.Sprintf("%s@%s", self.channel, self.channelRelay)
		}
		b = append(b, int2uintx(len(channelToken), 16)...)
		b = append(b, []byte(channelToken)...)
	case ChannelAuthVersion3:
		channelToken := JSONStr(AuthChannelInfo{
			Channel:     self.channel,
			Relay:       self.channelRelay,
			RelayRemote: self.relayForRemote,
			Host:        hostname,
		})
		b = append(b, int2uintx(len(channelToken), 16)...)
		b = append(b, []byte(channelToken)...)
	default:
		return nil, fmt.Errorf("unsupported auth version %v", version)
	}
	return b, nil
}

type AuthChannelInfo struct {
	Channel     string `json:"ch,omitempty"`
	Relay       string `json:"relay,omitempty"`
	RelayRemote bool   `json:"remote,omitempty"`
	Host        string `json:"h,omitempty"`
}

func int2uintx(num int, bit int) []byte {
	switch bit {
	case 16:
		bs := []byte{0, 0}
		binary.LittleEndian.PutUint16(bs, uint16(num))
		return bs
	case 32:
		bs := []byte{0, 0, 0, 0}
		binary.LittleEndian.PutUint32(bs, uint32(num))
		return bs
	default:
		panic("not support bit " + strconv.Itoa(bit))
	}
}

var (
	hostname     string
	hostnameHash string
)

func init() {
	if str := os.Getenv("POD_NAME"); str != "" {
		hostname = str
	} else if str = os.Getenv("HOSTNAME"); str != "" {
		hostname = str
	} else if str, _ = os.Hostname(); str != "" {
		hostname = str
	}
	hostnameHash = strings.ToLower(Sha256([]byte(hostname)))
}
