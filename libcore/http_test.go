package libcore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type waitingTransport struct{ started chan struct{} }

func (t waitingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	close(t.started)
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestCancelAbortsExecutingRequest(t *testing.T) {
	r := NewHttpClient().NewRequest().(*httpRequest)
	if err := r.SetURL("https://example.org"); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	r.h1h2Client.Transport = waitingTransport{started}
	result := make(chan error, 1)
	go func() { _, err := r.Execute(); result <- err }()
	<-started
	r.Cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not reach the executing transport")
	}
}

func TestCancelledH3ReturnsError(t *testing.T) {
	r := NewHttpClient().NewRequest().(*httpRequest)
	if err := r.SetURL("https://example.org"); err != nil {
		t.Fatal(err)
	}
	r.Cancel()
	response, err := r.doH3Direct()
	if response != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, %v", response, err)
	}
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestResponseSizeLimit(t *testing.T) {
	response := &httpResponse{Response: &http.Response{Body: io.NopCloser(endlessReader{})}}
	content, err := response.GetContent()
	if err == nil || content != nil {
		t.Fatal("oversize response accepted")
	}
}

func TestResponseCloseCancelsLifetimeOnce(t *testing.T) {
	calls := 0
	body := &cleanupBody{ReadCloser: io.NopCloser(strings.NewReader("ok")), cleanup: func() { calls++ }}
	response := &httpResponse{Response: &http.Response{Body: body}}
	content, err := response.GetContent()
	if err != nil || string(content) != "ok" {
		t.Fatalf("%q, %v", content, err)
	}
	response.Close()
	if calls != 1 {
		t.Fatalf("cleanup called %d times", calls)
	}
}
