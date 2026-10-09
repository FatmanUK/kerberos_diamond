package golden

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/transport"
)

// Direct is a Go KDC with **no shim in front of it**, published on
// every interface so that a client in a container can reach its HTTPS
// listener.
//
// It exists for one test. Every other case goes through
// kdiamond-proxy, which is the right topology for a client with no
// TLS module of its own and which is what the ordinary oracle is --
// but it means the TLS leg is exercised by the shim rather than by
// the client. This is the other half: a stock client built with
// upstream's k5tls module, pointed straight at the listener.
type Direct struct {
	// Port is the HTTPS port.
	Port int

	// CertPEM is the certificate, in the form http_anchors wants:
	// a PEM file the client is told to trust (load_anchor_file,
	// plugins/tls/k5tls/openssl.c:344-366, reached for a `FILE:'
	// prefix at :397-398).
	CertPEM string

	stop func()
}

// Close shuts it down.
func (d *Direct) Close() { d.stop() }

// ServeDirect starts the KDC's own HTTPS listener with nothing in
// front of it.
//
// The certificate carries a DNS name for the container's gateway
// alias rather than only an IP, because that is the name the client
// will put in its `kdc = https://...' line and the name the TLS
// module verifies: conn->http.servername is passed to the module's
// setup and OpenSSL checks it against the certificate
// (sendto_kdc.c:1245-1247).
func ServeDirect(
	ctx context.Context,
	d *Diamond,
) (*Direct, error) {
	cert, pemBytes, err := namedCert(HostAlias)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	srv := directServer(d, cert)
	go srv.ServeTLS(ln, "", "")
	sctx, cancel := context.WithCancel(ctx)
	go func() {
		<-sctx.Done()
		srv.Close()
	}()
	return &Direct{
		Port:    ln.Addr().(*net.TCPAddr).Port,
		CertPEM: string(pemBytes),
		stop:    func() { cancel(); srv.Close() },
	}, nil
}

// directServer is the same two routes Serve puts on the KDC.
func directServer(
	d *Diamond,
	cert tls.Certificate,
) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(transport.HealthPath, &transport.Health{
		Check: d.Store.Ping,
	})
	mux.Handle("/", &transport.Handler{
		Path:   ProxyPath,
		Handle: d.KDC.Handle,
	})
	return &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// namedCert makes a self-signed certificate for a DNS name, and
// returns it in both the forms needed: a tls.Certificate to serve
// with and PEM to hand the client as an anchor.
//
// Self-signed and used as its own anchor, which is what
// `http_anchors' is for: the client is told to trust this one
// certificate rather than a certificate authority, so there is no
// chain to build and no key material in the repository.
func namedCert(
	host string,
) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	})
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, out, nil
}
