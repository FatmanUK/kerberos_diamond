package golden

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/transport"
)

// Served is a running Go KDC with a shim in front of it.
//
// The topology is the one a deployment uses: the KDC is reached only
// over HTTPS, and a client without a TLS module of its own goes
// through the shim. The shim binds every interface so that a client
// inside the oracle's container can reach it; the KDC itself stays on
// loopback, because nothing but the shim has any business talking to
// it directly.
type Served struct {
	// ShimPort is the plain Kerberos TCP port a client dials.
	ShimPort int

	// URL is the KDC's KKDCP endpoint, for the record.
	URL string

	stop func()
}

// Close shuts both halves down.
func (s *Served) Close() { s.stop() }

// ProxyPath is the URL path the KDC answers KKDCP requests on.
const ProxyPath = "KdcProxy"

// Serve starts the Go KDC on HTTPS and a shim in front of it.
//
// The certificate is generated here and trusted only by the shim.
// That is honest about what the end-to-end check proves: the
// client-to-shim hop is cleartext, so the check demonstrates that an
// unmodified Kerberos 5 client interoperates with this KDC, not that
// the client negotiated the TLS itself. A client built *with* a TLS
// module reaches the KDC's listener directly and needs no shim at
// all.
func Serve(ctx context.Context, d *Diamond) (*Served, error) {
	cert, pool, err := selfSigned()
	if err != nil {
		return nil, err
	}
	srv, url, err := serveKDC(d, cert)
	if err != nil {
		return nil, err
	}
	shimLn, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		srv.Close()
		return nil, err
	}
	sctx, cancel := context.WithCancel(ctx)
	go serveShim(sctx, shimLn, url, pool)

	return &Served{
		ShimPort: shimLn.Addr().(*net.TCPAddr).Port,
		URL:      url,
		stop: func() {
			cancel()
			shimLn.Close()
			srv.Close()
		},
	}, nil
}

// serveKDC starts the HTTPS listener on loopback. Nothing but the
// shim has any business talking to it directly, so it is not
// published.
func serveKDC(
	d *Diamond,
	cert tls.Certificate,
) (*http.Server, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	srv := &http.Server{
		Handler: &transport.Handler{
			Path:   ProxyPath,
			Handle: d.KDC.Handle,
		},
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go srv.ServeTLS(ln, "", "")
	url := fmt.Sprintf("https://%s/%s",
		ln.Addr().String(), ProxyPath)
	return srv, url, nil
}

// serveShim runs the shim, which binds every interface so that a
// client inside the oracle's container can reach it.
func serveShim(
	ctx context.Context,
	ln net.Listener,
	url string,
	pool *x509.CertPool,
) {
	shim := &transport.Shim{
		Client: &transport.Client{
			URL:       url,
			Realm:     Realm,
			TLSConfig: &tls.Config{RootCAs: pool},
			Timeout:   20 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
	shim.Serve(ctx, ln)
}

// selfSigned makes a certificate for 127.0.0.1 and the pool that
// trusts it.
//
// Only the shim ever validates it, and the shim dials loopback, so
// one IP SAN is the whole requirement. It is generated rather than
// committed so that no key material lives in the repository.
func selfSigned() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "kdiamond-golden",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1), net.IPv6loopback,
		},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, pool, nil
}
