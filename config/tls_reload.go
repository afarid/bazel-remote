package config

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// tlsCertificateReloader is shared by the HTTP and gRPC TLS configs (including
// their clones). Only fully validated, immutable certificates are published.
type tlsCertificateReloader struct {
	mu                sync.Mutex
	certFile, keyFile string
	certificate       *tls.Certificate
	certHash, keyHash [sha256.Size]byte
	lastError         string
}

func newTLSCertificateReloader(certFile, keyFile string) (*tlsCertificateReloader, error) {
	r := &tlsCertificateReloader{certFile: certFile, keyFile: keyFile}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *tlsCertificateReloader) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.reload(); err != nil {
		// Avoid logging the same failure for every incoming connection. Keep
		// retrying so a repaired pair, or a future-dated cert, can be accepted.
		if message := err.Error(); message != r.lastError {
			log.Printf("TLS certificate reload failed; keeping the previous certificate: %s", message)
			r.lastError = message
		}
	} else {
		r.lastError = ""
	}
	return r.certificate, nil
}

// reload runs at startup and under mu during handshakes. Reading contents rather
// than watching file metadata also handles atomic renames and symlink rotations.
func (r *tlsCertificateReloader) reload() error {
	certPEM, err := os.ReadFile(r.certFile)
	if err != nil {
		return fmt.Errorf("error reading TLS certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return fmt.Errorf("error reading TLS key: %w", err)
	}
	certHash, keyHash := sha256.Sum256(certPEM), sha256.Sum256(keyPEM)
	if r.certificate != nil && r.certHash == certHash && r.keyHash == keyHash {
		return nil
	}

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("error reading certificate/key pair: %w", err)
	}
	if err := validateServerCertificate(&certificate, time.Now()); err != nil {
		return fmt.Errorf("invalid TLS certificate: %w", err)
	}

	// Commit the pair together. Failed or partial file updates leave all of the
	// previously accepted state intact and will be retried on the next handshake.
	r.certificate = &certificate
	r.certHash, r.keyHash = certHash, keyHash
	return nil
}

func validateServerCertificate(certificate *tls.Certificate, now time.Time) error {
	if len(certificate.Certificate) == 0 {
		return fmt.Errorf("empty certificate chain")
	}
	chain := make([]*x509.Certificate, 0, len(certificate.Certificate))
	var previous *x509.Certificate
	for i, der := range certificate.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parsing certificate %d: %w", i, err)
		}
		if now.Before(cert.NotBefore) {
			return fmt.Errorf("certificate %d is not valid before %s", i, cert.NotBefore)
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("certificate %d expired at %s", i, cert.NotAfter)
		}
		if i == 0 {
			certificate.Leaf = cert
		} else if err := previous.CheckSignatureFrom(cert); err != nil {
			return fmt.Errorf("invalid certificate chain at certificate %d: %w", i, err)
		}
		chain = append(chain, cert)
		previous = cert
	}

	// Validate constraints within the supplied chain without requiring public
	// trust roots or a known server hostname. The last supplied certificate may
	// be an intermediate, or the leaf itself for a self-signed/leaf-only file.
	// Clients still decide whether to trust this chain and hostname.
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	for i := 1; i < len(chain)-1; i++ {
		intermediates.AddCert(chain[i])
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("verifying supplied certificate chain: %w", err)
	}
	return nil
}
