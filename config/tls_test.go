package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type reloadTestMaterial struct {
	certPEM []byte
	keyPEM  []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func reloadTestCertificate(t *testing.T, serial int64, mutate func(*x509.Certificate), parent *reloadTestMaterial) reloadTestMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if mutate != nil {
		mutate(template)
	}
	issuer, signingKey := template, key
	if parent != nil {
		issuer, signingKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return reloadTestMaterial{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		cert:    cert,
		key:     key,
	}
}

func reloadTestWrite(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
}

func reloadTestSerial(cert *tls.Certificate) (int64, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return 0, fmt.Errorf("no certificate returned")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return 0, err
	}
	return leaf.SerialNumber.Int64(), nil
}

func reloadTestWantSerial(t *testing.T, r *tlsCertificateReloader, want int64) {
	t.Helper()
	cert, err := r.getCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("certificate callback failed: %v", err)
	}
	got, err := reloadTestSerial(cert)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("certificate serial = %d, want %d", got, want)
	}
}

func TestTLSCertificateReloaderRejectsInvalidInitialCertificate(t *testing.T) {
	valid := reloadTestCertificate(t, 1, nil, nil)
	other := reloadTestCertificate(t, 2, nil, nil)
	expired := reloadTestCertificate(t, 3, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-2 * time.Hour)
		c.NotAfter = time.Now().Add(-time.Hour)
	}, nil)
	future := reloadTestCertificate(t, 4, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(time.Hour)
		c.NotAfter = time.Now().Add(2 * time.Hour)
	}, nil)
	clientOnly := reloadTestCertificate(t, 5, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}, nil)
	unknownUsage := reloadTestCertificate(t, 6, func(c *x509.Certificate) {
		c.ExtKeyUsage = nil
		c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
	}, nil)
	cases := []struct {
		name string
		cert []byte
		key  []byte
	}{
		{"missing certificate", nil, valid.keyPEM},
		{"missing key", valid.certPEM, nil},
		{"malformed certificate", []byte("not a certificate"), valid.keyPEM},
		{"malformed key", valid.certPEM, []byte("not a key")},
		{"mismatched key", valid.certPEM, other.keyPEM},
		{"expired", expired.certPEM, expired.keyPEM},
		{"not yet valid", future.certPEM, future.keyPEM},
		{"client only", clientOnly.certPEM, clientOnly.keyPEM},
		{"unknown usage only", unknownUsage.certPEM, unknownUsage.keyPEM},
		{"malformed chain certificate", append(append([]byte{}, valid.certPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})...), valid.keyPEM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			if tc.cert != nil {
				reloadTestWrite(t, certFile, tc.cert)
			}
			if tc.key != nil {
				reloadTestWrite(t, keyFile, tc.key)
			}
			if _, err := newTLSCertificateReloader(certFile, keyFile); err == nil {
				t.Fatal("expected invalid initial certificate to fail")
			}
		})
	}
}

func TestTLSCertificateReloaderFallbackAndRecovery(t *testing.T) {
	original := reloadTestCertificate(t, 1, nil, nil)
	replacement := reloadTestCertificate(t, 2, nil, nil)
	expired := reloadTestCertificate(t, 3, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-2 * time.Hour)
		c.NotAfter = time.Now().Add(-time.Hour)
	}, nil)
	future := reloadTestCertificate(t, 4, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(time.Hour)
		c.NotAfter = time.Now().Add(2 * time.Hour)
	}, nil)
	clientOnly := reloadTestCertificate(t, 5, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}, nil)
	unknownUsage := reloadTestCertificate(t, 6, func(c *x509.Certificate) {
		c.ExtKeyUsage = nil
		c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
	}, nil)
	cases := []struct {
		name string
		cert []byte
		key  []byte
	}{
		{"missing certificate", nil, original.keyPEM},
		{"missing key", original.certPEM, nil},
		{"malformed certificate", []byte("invalid PEM"), original.keyPEM},
		{"malformed key", original.certPEM, []byte("invalid PEM")},
		{"partial rotation", replacement.certPEM, original.keyPEM},
		{"expired", expired.certPEM, expired.keyPEM},
		{"not yet valid", future.certPEM, future.keyPEM},
		{"client only", clientOnly.certPEM, clientOnly.keyPEM},
		{"unknown usage only", unknownUsage.certPEM, unknownUsage.keyPEM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			reloadTestWrite(t, certFile, original.certPEM)
			reloadTestWrite(t, keyFile, original.keyPEM)
			r, err := newTLSCertificateReloader(certFile, keyFile)
			if err != nil {
				t.Fatal(err)
			}
			if tc.cert == nil {
				if err := os.Remove(certFile); err != nil {
					t.Fatal(err)
				}
			} else {
				reloadTestWrite(t, certFile, tc.cert)
			}
			if tc.key == nil {
				if err := os.Remove(keyFile); err != nil {
					t.Fatal(err)
				}
			} else {
				reloadTestWrite(t, keyFile, tc.key)
			}
			reloadTestWantSerial(t, r, 1)
			// Invalid files stay present across multiple handshakes.
			reloadTestWantSerial(t, r, 1)
			reloadTestWrite(t, certFile, replacement.certPEM)
			reloadTestWrite(t, keyFile, replacement.keyPEM)
			reloadTestWantSerial(t, r, 2)
		})
	}
}

func TestTLSCertificateReloaderDetectsChangesWithoutMetadataChanges(t *testing.T) {
	original := reloadTestCertificate(t, 1, nil, nil)
	replacement := reloadTestCertificate(t, 2, nil, nil)
	pad := func(a, b []byte) ([]byte, []byte) {
		size := max(len(a), len(b)) + 8
		return append(a, bytes.Repeat([]byte("\n"), size-len(a))...), append(b, bytes.Repeat([]byte("\n"), size-len(b))...)
	}
	original.certPEM, replacement.certPEM = pad(original.certPEM, replacement.certPEM)
	original.keyPEM, replacement.keyPEM = pad(original.keyPEM, replacement.keyPEM)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	stamp := time.Unix(1700000000, 0)
	write := func(material reloadTestMaterial) {
		reloadTestWrite(t, certFile, material.certPEM)
		reloadTestWrite(t, keyFile, material.keyPEM)
		for _, path := range []string{certFile, keyFile} {
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(original)
	r, err := newTLSCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	write(replacement)
	reloadTestWantSerial(t, r, 2)
}

func TestTLSCertificateReloaderFollowsSymlinkRotation(t *testing.T) {
	dir := t.TempDir()
	for i := int64(1); i <= 2; i++ {
		versionDir := filepath.Join(dir, fmt.Sprint(i))
		if err := os.Mkdir(versionDir, 0700); err != nil {
			t.Fatal(err)
		}
		material := reloadTestCertificate(t, i, nil, nil)
		reloadTestWrite(t, filepath.Join(versionDir, "cert.pem"), material.certPEM)
		reloadTestWrite(t, filepath.Join(versionDir, "key.pem"), material.keyPEM)
	}
	current := filepath.Join(dir, "current")
	if err := os.Symlink("1", current); err != nil {
		t.Fatal(err)
	}
	r, err := newTLSCertificateReloader(filepath.Join(current, "cert.pem"), filepath.Join(current, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	reloadTestWantSerial(t, r, 1)
	if err := os.Symlink("2", filepath.Join(dir, "next")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "next"), current); err != nil {
		t.Fatal(err)
	}
	reloadTestWantSerial(t, r, 2)
}

func TestTLSCertificateReloaderValidatesChain(t *testing.T) {
	makeCA := func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCertSign
		c.ExtKeyUsage = nil
	}
	ca := reloadTestCertificate(t, 10, makeCA, nil)
	otherCA := reloadTestCertificate(t, 11, makeCA, nil)
	leaf := reloadTestCertificate(t, 1, nil, &ca)
	validChain := append(append([]byte{}, leaf.certPEM...), ca.certPEM...)
	invalidChain := append(append([]byte{}, leaf.certPEM...), otherCA.certPEM...)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	reloadTestWrite(t, certFile, validChain)
	reloadTestWrite(t, keyFile, leaf.keyPEM)
	r, err := newTLSCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	reloadTestWrite(t, certFile, invalidChain)
	if _, err := newTLSCertificateReloader(certFile, keyFile); err == nil {
		t.Fatal("chain signed by an unrelated CA accepted")
	}
	reloadTestWantSerial(t, r, 1)
}

func TestTLSCertificateReloaderConcurrentCallbacks(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	original := reloadTestCertificate(t, 1, nil, nil)
	replacement := reloadTestCertificate(t, 2, nil, nil)
	reloadTestWrite(t, certFile, original.certPEM)
	reloadTestWrite(t, keyFile, original.keyPEM)
	r, err := newTLSCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	errors := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				cert, err := r.getCertificate(&tls.ClientHelloInfo{})
				if err != nil {
					errors <- err
					return
				}
				serial, err := reloadTestSerial(cert)
				if err != nil {
					errors <- err
					return
				}
				if serial != 1 && serial != 2 {
					errors <- fmt.Errorf("unexpected certificate serial %d", serial)
					return
				}
			}
		}()
	}
	// Concurrent handshakes can observe missing or mismatched files during rotation,
	// but must always receive a complete, previously validated certificate.
	reloadTestWrite(t, certFile, replacement.certPEM)
	reloadTestWrite(t, keyFile, replacement.keyPEM)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	reloadTestWantSerial(t, r, 2)
}

func TestTLSCertificateReloaderRejectsInvalidChainConstraints(t *testing.T) {
	original := reloadTestCertificate(t, 1, nil, nil)
	clientCA := reloadTestCertificate(t, 10, func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCertSign
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}, nil)
	serverFromClientCA := reloadTestCertificate(t, 2, nil, &clientCA)
	unknownCritical := reloadTestCertificate(t, 3, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4},
			Critical: true,
			Value:    []byte{5, 0}, // ASN.1 NULL, for an unknown extension.
		}}
	}, nil)
	cases := []struct {
		name string
		cert []byte
		key  []byte
	}{
		{
			name: "issuer restricted to client authentication",
			cert: append(append([]byte{}, serverFromClientCA.certPEM...), clientCA.certPEM...),
			key:  serverFromClientCA.keyPEM,
		},
		{
			name: "unknown critical extension",
			cert: unknownCritical.certPEM,
			key:  unknownCritical.keyPEM,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			reloadTestWrite(t, certFile, original.certPEM)
			reloadTestWrite(t, keyFile, original.keyPEM)
			r, err := newTLSCertificateReloader(certFile, keyFile)
			if err != nil {
				t.Fatal(err)
			}
			reloadTestWrite(t, certFile, tc.cert)
			reloadTestWrite(t, keyFile, tc.key)
			if _, err := newTLSCertificateReloader(certFile, keyFile); err == nil {
				t.Fatal("invalid certificate constraints accepted at startup")
			}
			reloadTestWantSerial(t, r, 1)
		})
	}
}
