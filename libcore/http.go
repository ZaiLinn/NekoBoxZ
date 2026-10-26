package libcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"libcore/device"
	"libcore/ech"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

const maxHTTPText = 32 * 1024 * 1024
const maxHTTPAsset = 256 * 1024 * 1024

var errFailConnectSocks5 = errors.New("fail connect socks5")

type HTTPClient interface {
	RestrictedTLS()
	ModernTLS()
	PinnedTLS12()
	PinnedSHA256(sumHex string)
	TrySocks5(port int32)
	TryH3Direct()
	KeepAlive()
	NewRequest() HTTPRequest
	Close()
}

type HTTPRequest interface {
	SetURL(link string) error
	SetMethod(method string)
	SetHeader(key string, value string)
	SetContent(content []byte)
	SetContentString(content string)
	SetUserAgent(userAgent string)
	AllowInsecure()
	Execute() (HTTPResponse, error)
	Cancel()
}

type HTTPResponse interface {
	Close() error
	GetHeader(string) *StringBox
	GetContent() ([]byte, error)
	GetContentString() (*StringBox, error)
	WriteTo(path string) error
}

var (
	_ HTTPClient   = (*httpClient)(nil)
	_ HTTPRequest  = (*httpRequest)(nil)
	_ HTTPResponse = (*httpResponse)(nil)
)

type httpClient struct {
	tls           tls.Config
	h1h2Transport http.Transport
	h1h2Client    http.Client
	trySocks5     bool
	tryH3Direct   bool
}

func NewHttpClient() HTTPClient {
	client := new(httpClient)
	client.h1h2Client.Transport = &client.h1h2Transport
	client.h1h2Client.Timeout = 30 * time.Second
	client.h1h2Transport.TLSHandshakeTimeout = 10 * time.Second
	client.h1h2Transport.ResponseHeaderTimeout = 15 * time.Second
	client.h1h2Transport.MaxResponseHeaderBytes = 1024 * 1024
	client.h1h2Transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	client.h1h2Transport.TLSClientConfig = &client.tls
	client.h1h2Transport.DisableKeepAlives = true
	return client
}

func (c *httpClient) ModernTLS() {
	c.tls.MinVersion = tls.VersionTLS12
	// c.tls.CipherSuites = nekoutils.Map(tls.CipherSuites(), func(it *tls.CipherSuite) uint16 { return it.ID })
}

func (c *httpClient) RestrictedTLS() {
	c.tls.MinVersion = tls.VersionTLS13
	// c.tls.CipherSuites = nekoutils.Map(nekoutils.Filter(tls.CipherSuites(), func(it *tls.CipherSuite) bool {
	// 	return nekoutils.Contains(it.SupportedVersions, uint16(tls.VersionTLS13))
	// }), func(it *tls.CipherSuite) uint16 {
	// 	return it.ID
	// })
}

func (c *httpClient) PinnedTLS12() {
	c.tls.MinVersion = tls.VersionTLS12
	c.tls.MaxVersion = tls.VersionTLS12
}

func (c *httpClient) PinnedSHA256(sumHex string) {
	c.tls.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, rawCert := range rawCerts {
			certSum := sha256.Sum256(rawCert)
			if sumHex == hex.EncodeToString(certSum[:]) {
				return nil
			}
		}
		return errors.New("pinned sha256 sum mismatch")
	}
}

func (c *httpClient) TrySocks5(port int32) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	c.h1h2Transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		for {
			socksConn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(int(port)))
			if err != nil {
				if c.tryH3Direct {
					return nil, errFailConnectSocks5
				}
				break
			}
			if deadline, ok := ctx.Deadline(); ok {
				_ = socksConn.SetDeadline(deadline)
			}
			stopCancel := context.AfterFunc(ctx, func() { socksConn.Close() })
			_, err = socks.ClientHandshake5(socksConn, socks5.CommandConnect, metadata.ParseSocksaddr(addr), "", "")
			if !stopCancel() && err == nil {
				err = ctx.Err()
			}
			if err != nil {
				socksConn.Close()
				if c.tryH3Direct {
					return nil, errFailConnectSocks5
				}
				break
			}
			_ = socksConn.SetDeadline(time.Time{})
			return socksConn, nil
		}
		return dialer.DialContext(ctx, network, addr)
	}
	c.trySocks5 = true
}

func (c *httpClient) TryH3Direct() {
	c.tryH3Direct = true
}

func (c *httpClient) KeepAlive() {
	c.h1h2Transport.ForceAttemptHTTP2 = true
	c.h1h2Transport.DisableKeepAlives = false
}

func (c *httpClient) NewRequest() HTTPRequest {
	req := &httpRequest{httpClient: c}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	req.cancel = cancel
	req.request = http.Request{
		Method: "GET",
		Header: http.Header{},
	}
	req.request = *req.request.WithContext(ctx)
	return req
}

func (c *httpClient) Close() {
	c.h1h2Transport.CloseIdleConnections()
}

type httpRequest struct {
	*httpClient
	request http.Request
	cancel  context.CancelFunc
}

func (r *httpRequest) Cancel() { r.cancel() }

type cleanupBody struct {
	io.ReadCloser
	once    sync.Once
	cleanup func()
}

func (b *cleanupBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cleanup)
	return err
}

func (r *httpRequest) AllowInsecure() {
	r.tls.InsecureSkipVerify = true
}

func (r *httpRequest) SetURL(link string) (err error) {
	r.request.URL, err = url.Parse(link)
	if err != nil {
		return
	}
	if r.request.URL.User != nil {
		user := r.request.URL.User.Username()
		password, _ := r.request.URL.User.Password()
		r.request.SetBasicAuth(user, password)
	}
	return
}

func (r *httpRequest) SetMethod(method string) {
	r.request.Method = method
}

func (r *httpRequest) SetHeader(key string, value string) {
	r.request.Header.Set(key, value)
}

func (r *httpRequest) SetUserAgent(userAgent string) {
	r.request.Header.Set("User-Agent", userAgent)
}

func (r *httpRequest) SetContent(content []byte) {
	buffer := bytes.Buffer{}
	buffer.Write(content)
	r.request.Body = io.NopCloser(bytes.NewReader(buffer.Bytes()))
	r.request.ContentLength = int64(len(content))
}

func (r *httpRequest) SetContentString(content string) {
	r.SetContent([]byte(content))
}

func (r *httpRequest) Execute() (response HTTPResponse, err error) {
	defer device.DeferPanicToError("http execute", func(e error) { err = e })
	defer func() {
		if response == nil {
			r.cancel()
		}
	}()
	if r.tryH3Direct && !r.trySocks5 {
		return r.doH3Direct()
	}
	rsp, err := r.h1h2Client.Do(&r.request)
	if err != nil {
		if r.tryH3Direct && errors.Is(err, errFailConnectSocks5) {
			return r.doH3Direct()
		}
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		rsp.Body.Close()
		return nil, fmt.Errorf("HTTP %s", rsp.Status)
	}
	rsp.Body = &cleanupBody{ReadCloser: rsp.Body, cleanup: r.cancel}
	return &httpResponse{Response: rsp}, nil
}

type requestResult struct {
	index          int
	response       *http.Response
	err            error
	cancel         context.CancelFunc
	closeTransport func()
}

func (r *httpRequest) doH3Direct() (HTTPResponse, error) {
	if err := r.request.Context().Err(); err != nil {
		return nil, err
	}
	// A single lifetime covers dial, ECH lookup, handshake, headers and response body.
	// The winner keeps its context until Body.Close; every loser is cancelled immediately.
	resultCh := make(chan requestResult)
	finished := make(chan struct{})
	defer close(finished)
	count := 2
	if r.request.URL.Scheme == "http" {
		count = 1
	}
	cancels := make([]context.CancelFunc, count)
	winner := -1
	defer func() {
		for i, cancel := range cancels {
			if i != winner {
				cancel()
			}
		}
	}()
	for i := 0; i < count; i++ {
		ctx, cancel := context.WithCancel(r.request.Context())
		cancels[i] = cancel
		go func(i int, ctx context.Context, cancel context.CancelFunc) {
			var transport http.RoundTripper
			var closeTransport func()
			if i == 0 {
				t := &http.Transport{
					TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
					MaxResponseHeaderBytes: 1024 * 1024, DisableKeepAlives: true,
					DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
					DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
						if err != nil {
							return nil, err
						}
						host, _, err := net.SplitHostPort(addr)
						if err != nil {
							conn.Close()
							return nil, err
						}
						cfg := ech.NewECHClientConfig(host, &r.tls, gLocalDNSTransport)
						tlsConn, err := cfg.Client(ctx, conn)
						if err != nil {
							conn.Close()
							return nil, err
						}
						if err = tlsConn.HandshakeContext(ctx); err != nil {
							conn.Close()
							return nil, err
						}
						return tlsConn, nil
					},
				}
				transport, closeTransport = t, t.CloseIdleConnections
			} else {
				t := &http3.Transport{TLSClientConfig: r.tls.Clone(), QUICConfig: &quic.Config{MaxIdleTimeout: 10 * time.Second}}
				transport, closeTransport = t, func() { t.Close() }
			}
			rsp, err := (&http.Client{Transport: transport}).Do(r.request.Clone(ctx))
			result := requestResult{i, rsp, err, cancel, closeTransport}
			select {
			case resultCh <- result:
				// Receiver owns every resource from this point.
			case <-finished:
				if rsp != nil {
					rsp.Body.Close()
				}
				cancel()
				closeTransport()
			}
		}(i, ctx, cancel)
	}
	var finalErr error
	for remaining := count; remaining > 0; remaining-- {
		select {
		case result := <-resultCh:
			rsp := result.response
			if result.err == nil && rsp != nil && rsp.StatusCode == http.StatusOK {
				winner = result.index
				rsp.Body = &cleanupBody{ReadCloser: rsp.Body, cleanup: func() { result.cancel(); result.closeTransport(); r.cancel() }}
				return &httpResponse{Response: rsp}, nil
			}
			if rsp != nil {
				rsp.Body.Close()
			}
			result.cancel()
			result.closeTransport()
			if result.err != nil {
				finalErr = errors.Join(finalErr, result.err)
			} else if rsp != nil {
				finalErr = errors.Join(finalErr, fmt.Errorf("HTTP %s", rsp.Status))
			}
		case <-r.request.Context().Done():
			return nil, r.request.Context().Err()
		}
	}
	if finalErr == nil {
		finalErr = errors.New("all HTTP transports failed")
	}
	return nil, finalErr
}

type httpResponse struct {
	*http.Response

	getContentOnce sync.Once
	content        []byte
	contentError   error
}

func (h *httpResponse) Close() error { return h.Body.Close() }

func (h *httpResponse) errorString() string {
	content, err := h.getContentString()
	if err != nil {
		return fmt.Sprint("HTTP ", h.Status)
	}
	if len(content) > 100 {
		content = content[:100] + " ..."
	}
	return fmt.Sprint("HTTP ", h.Status, ": ", content)
}

func (h *httpResponse) GetHeader(key string) *StringBox {
	return wrapString(h.Header.Get(key))
}

func (h *httpResponse) GetContent() ([]byte, error) {
	h.getContentOnce.Do(func() {
		defer h.Body.Close()
		h.content, h.contentError = io.ReadAll(io.LimitReader(h.Body, maxHTTPText+1))
		if len(h.content) > maxHTTPText {
			h.content = nil
			h.contentError = errors.New("HTTP response too large")
		}
	})
	return h.content, h.contentError
}

func (h *httpResponse) GetContentString() (*StringBox, error) {
	content, err := h.getContentString()
	if err != nil {
		return nil, err
	}
	return wrapString(content), nil
}

func (h *httpResponse) getContentString() (string, error) {
	content, err := h.GetContent()
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (h *httpResponse) WriteTo(path string) error {
	defer h.Body.Close()
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	n, err := io.Copy(file, io.LimitReader(h.Body, maxHTTPAsset+1))
	if n > maxHTTPAsset {
		return errors.New("HTTP asset too large")
	}
	return err
}
