package libcore

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/option"
)

type testLocalDNS struct{ handle int64 }

func (d testLocalDNS) Raw() bool                                     { return true }
func (d testLocalDNS) NetworkHandle() int64                          { return d.handle }
func (d testLocalDNS) Lookup(*ExchangeContext, string, string) error { return nil }
func (d testLocalDNS) Exchange(*ExchangeContext, []byte) error       { return nil }

func TestRawDNSRequiresUnderlyingNetwork(t *testing.T) {
	previous := rawQueryFunc
	defer func() { rawQueryFunc = previous }()
	called := false
	rawQueryFunc = func(int64, []byte) ([]byte, error) {
		called = true
		return nil, nil
	}

	transport := &platformLocalDNSTransport{iif: testLocalDNS{}, raw: true}
	question := new(mDNS.Msg)
	question.SetQuestion("example.org.", mDNS.TypeA)
	_, err := transport.Exchange(context.Background(), question)
	if !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("expected ENETUNREACH without an underlying network, got %v", err)
	}
	if called {
		t.Fatal("raw DNS query was sent without an underlying network")
	}
}

type successfulLookupDNS struct{ testLocalDNS }

func (successfulLookupDNS) Raw() bool { return false }
func (successfulLookupDNS) Lookup(c *ExchangeContext, _, _ string) error {
	c.Success("192.0.2.1")
	return nil
}

func TestLookupDNSSuccessCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	transport := newPlatformTransport(successfulLookupDNS{}, "", option.LocalDNSServerOptions{})
	question := new(mDNS.Msg)
	question.SetQuestion("example.org.", mDNS.TypeA)
	answer, err := transport.Exchange(ctx, question)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Answer) != 1 || answer.Answer[0].(*mDNS.A).A.String() != "192.0.2.1" {
		t.Fatalf("unexpected answer: %v", answer)
	}
}
