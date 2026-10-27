package libcore

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

// A SOCKS peer that accepts the greeting but never responds. net.Pipe needs no
// listening port, so these tests also run in the restricted local environment.
func stalledSOCKSPeer(t *testing.T) (contextDialFunc, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	started, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		if _, err := io.ReadFull(server, make([]byte, 3)); err != nil {
			return
		}
		close(started)
		_, _ = io.Copy(io.Discard, server)
	}()
	return func(context.Context, string, string) (net.Conn, error) { return client, nil }, started, closed
}

func TestSOCKSHandshakeHasIndependentDeadline(t *testing.T) {
	dial, _, closed := stalledSOCKSPeer(t)
	start := time.Now()
	conn, err := socksDialContext(dial, "proxy", 40*time.Millisecond, func() bool { return true })(
		context.Background(), "tcp", "192.0.2.1:443")
	if conn != nil || err == nil || time.Since(start) > time.Second {
		t.Fatalf("handshake did not time out: %v, %v", conn, err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timed out handshake leaked the connection")
	}
}

func TestCancelClosesTransportSOCKSHandshake(t *testing.T) {
	dial, started, closed := stalledSOCKSPeer(t)
	r := NewHttpClient().NewRequest().(*httpRequest)
	if err := r.SetURL("https://example.org"); err != nil {
		t.Fatal(err)
	}
	r.h1h2Transport.DialContext = socksDialContext(dial, "proxy", time.Minute, func() bool { return true })
	result := make(chan error, 1)
	go func() { _, err := r.Execute(); result <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("SOCKS handshake did not start")
	}
	r.Cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP request did not cancel")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("HTTP cancellation left SOCKS negotiation running")
	}
}

func TestSuccessfulSOCKSHandshakeClearsDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverError := make(chan error, 1)
	go func() {
		reader := varbin.StubReader(server)
		_, err := socks5.ReadAuthRequest(reader)
		if err == nil {
			err = socks5.WriteAuthResponse(server, socks5.AuthResponse{Method: socks5.AuthTypeNotRequired})
		}
		if err == nil {
			_, err = socks5.ReadRequest(reader)
		}
		if err == nil {
			_, err = server.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		}
		serverError <- err
	}()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	conn, err := socksDialContext(dial, "proxy", 100*time.Millisecond, func() bool { return true })(
		context.Background(), "tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	// The negotiation timer must not close or expire a successfully returned stream.
	time.Sleep(150 * time.Millisecond)
	go func() { _, _ = server.Write([]byte("ok")) }()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("successful connection kept the handshake deadline: %q, %v", buf, err)
	}
}
