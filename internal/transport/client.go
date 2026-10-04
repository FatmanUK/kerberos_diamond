package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// Client posts Kerberos messages to a KKDCP URL over TLS.
type Client struct {
	// URL is the KDC's KKDCP endpoint, including the path.
	URL string

	// Realm travels as target-domain. Upstream's client always
	// sends it (sendto_kdc.c:627), so this does too, even though
	// a single-realm proxy has no use for it.
	Realm string

	// TLSConfig is optional; nil uses Go's defaults, which verify
	// the certificate against the system roots.
	TLSConfig *tls.Config

	// Timeout bounds one exchange. Zero means 30 seconds.
	Timeout time.Duration

	http *http.Client
}

// Send posts one message and returns the reply.
func (c *Client) Send(
	ctx context.Context,
	msg []byte,
) ([]byte, error) {
	body, err := wire.MarshalKDCProxyMessage(
		wire.KDCProxyMessage{
			KerbMessage:  wire.Frame(msg),
			TargetDomain: c.Realm,
		})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ContentType)
	// Upstream sends this User-Agent, and some proxies key their
	// behaviour on it (sendto_kdc.c:638).
	req.Header.Set("User-Agent", "kerberos/1.0")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readReply(resp)
}

func readReply(resp *http.Response) ([]byte, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KKDCP: %s", resp.Status)
	}
	body, err := io.ReadAll(http.MaxBytesReader(
		nil, resp.Body, wire.MaxFrame+1024))
	if err != nil {
		return nil, err
	}
	pm, err := wire.UnmarshalKDCProxyMessage(body)
	if err != nil {
		return nil, err
	}
	return wire.Unframe(pm.KerbMessage)
}

func (c *Client) client() *http.Client {
	if c.http != nil {
		return c.http
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	c.http = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: c.TLSConfig,
		},
	}
	return c.http
}
