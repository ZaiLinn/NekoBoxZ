package libcore

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type httpRequestContextKey struct{}
type contextDialFunc func(context.Context, string, string) (net.Conn, error)

func socksDialContext(dial contextDialFunc, proxy string, timeout time.Duration, failFast func() bool) contextDialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// Always bound negotiation, including callers whose dial context has no deadline.
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if requestCtx, ok := ctx.Value(httpRequestContextKey{}).(context.Context); ok {
			stop := context.AfterFunc(requestCtx, cancel)
			defer stop()
			if requestCtx.Err() != nil {
				cancel()
			}
		}
		conn, err := dial(dialCtx, "tcp", proxy)
		if err == nil {
			deadline, _ := dialCtx.Deadline()
			err = conn.SetDeadline(deadline)
			if err == nil {
				stop := context.AfterFunc(dialCtx, func() { conn.Close() })
				_, err = socks.ClientHandshake5(conn, socks5.CommandConnect, metadata.ParseSocksaddr(address), "", "")
				if !stop() && err == nil {
					err = dialCtx.Err()
				}
			}
			if err == nil {
				err = conn.SetDeadline(time.Time{})
			}
			if err == nil {
				return conn, nil
			}
			conn.Close()
		}
		if dialCtx.Err() != nil {
			return nil, dialCtx.Err()
		}
		if failFast() {
			return nil, errFailConnectSocks5
		}
		// Preserve the existing direct fallback after a failed proxy handshake. It is
		// still tied to the request lifetime and the overall dial budget.
		return dial(dialCtx, network, address)
	}
}
