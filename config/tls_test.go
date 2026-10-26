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

func reloadTestWait(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func reloadTestNewReloader(t *testing.T, certFile, keyFile string) *tlsCertificateReloader {
	t.Helper()
	r, err := newTLSCertificateReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Errorf("closing certificate watcher: %v", err)
		}
	})
	return r
}

func reloadTestWantSerial(t *testing.T, r *tlsCertificateReloader, want int64) {
	t.Helper()
	// Read the proactively updated cache before invoking any TLS callback. A
	// handshake-driven loader cannot make this condition succeed.
	reloadTestWait(t, fmt.Sprintf("cached certificate serial %d", want), func() bool {
		got, err := reloadTestSerial(r.certificate.Load())
		return err == nil && got == want
	})
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

func reloadTestWantFallback(t *testing.T, r *tlsCertificateReloader, before uint64, previous *tls.Certificate) {
	t.Helper()
	reloadTestWait(t, "watcher to process invalid replacement", func() bool {
		return r.processed.Load() > before
	})
	if r.certificate.Load() != previous {
		t.Fatal("invalid replacement changed the cached certificate")
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
			if unexpected, err := newTLSCertificateReloader(certFile, keyFile); err == nil {
				_ = unexpected.Close()
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
			r := reloadTestNewReloader(t, certFile, keyFile)
			previous, before := r.certificate.Load(), r.processed.Load()
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
			reloadTestWantFallback(t, r, before, previous)
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
	r := reloadTestNewReloader(t, certFile, keyFile)
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
	r := reloadTestNewReloader(t, filepath.Join(current, "cert.pem"), filepath.Join(current, "key.pem"))
	reloadTestWantSerial(t, r, 1)
	if err := os.Symlink("2", filepath.Join(dir, "next")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "next"), current); err != nil {
		t.Fatal(err)
	}
	reloadTestWantSerial(t, r, 2)
	// The watcher must follow the new target after the directory symlink moves.
	third := reloadTestCertificate(t, 3, nil, nil)
	reloadTestWrite(t, filepath.Join(dir, "2", "cert.pem"), third.certPEM)
	reloadTestWrite(t, filepath.Join(dir, "2", "key.pem"), third.keyPEM)
	reloadTestWantSerial(t, r, 3)
}

func TestTLSCertificateReloaderFollowsFileSymlinkTargets(t *testing.T) {
	dir := t.TempDir()
	logicalDir := filepath.Join(dir, "configured")
	if err := os.Mkdir(logicalDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"first", "second"} {
		if err := os.Mkdir(filepath.Join(dir, version), 0700); err != nil {
			t.Fatal(err)
		}
	}
	original := reloadTestCertificate(t, 1, nil, nil)
	replacement := reloadTestCertificate(t, 2, nil, nil)
	third := reloadTestCertificate(t, 3, nil, nil)
	fourth := reloadTestCertificate(t, 4, nil, nil)
	firstDir, secondDir := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	reloadTestWrite(t, filepath.Join(firstDir, "cert.pem"), original.certPEM)
	reloadTestWrite(t, filepath.Join(firstDir, "key.pem"), original.keyPEM)
	reloadTestWrite(t, filepath.Join(secondDir, "cert.pem"), third.certPEM)
	reloadTestWrite(t, filepath.Join(secondDir, "key.pem"), third.keyPEM)
	certFile, keyFile := filepath.Join(logicalDir, "cert.pem"), filepath.Join(logicalDir, "key.pem")
	for _, path := range []string{certFile, keyFile} {
		if err := os.Symlink(filepath.Join(firstDir, filepath.Base(path)), path); err != nil {
			t.Fatal(err)
		}
	}
	r := reloadTestNewReloader(t, certFile, keyFile)
	// Writes occur outside the configured directory without changing its links.
	reloadTestWrite(t, filepath.Join(firstDir, "cert.pem"), replacement.certPEM)
	reloadTestWrite(t, filepath.Join(firstDir, "key.pem"), replacement.keyPEM)
	reloadTestWantSerial(t, r, 2)
	for _, path := range []string{certFile, keyFile} {
		if err := os.Symlink(filepath.Join(secondDir, filepath.Base(path)), path+".new"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".new", path); err != nil {
			t.Fatal(err)
		}
	}
	reloadTestWantSerial(t, r, 3)
	// Reconcile target watches after replacing the file symlinks too.
	reloadTestWrite(t, filepath.Join(secondDir, "cert.pem"), fourth.certPEM)
	reloadTestWrite(t, filepath.Join(secondDir, "key.pem"), fourth.keyPEM)
	reloadTestWantSerial(t, r, 4)
}

func TestTLSCertificateReloaderFollowsKubernetesProjection(t *testing.T) {
	dir := t.TempDir()
	for serial, version := range []string{"..2026_01", "..2026_02"} {
		versionDir := filepath.Join(dir, version)
		if err := os.Mkdir(versionDir, 0700); err != nil {
			t.Fatal(err)
		}
		material := reloadTestCertificate(t, int64(serial+1), nil, nil)
		reloadTestWrite(t, filepath.Join(versionDir, "tls.crt"), material.certPEM)
		reloadTestWrite(t, filepath.Join(versionDir, "tls.key"), material.keyPEM)
	}
	// Kubernetes keeps these public file links fixed and atomically replaces
	// only the ..data directory link when projected secret contents change.
	if err := os.Symlink("..2026_01", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls.crt", "tls.key"} {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	r := reloadTestNewReloader(t, filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err := os.Symlink("..2026_02", filepath.Join(dir, "..data_tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	reloadTestWantSerial(t, r, 2)
	third := reloadTestCertificate(t, 3, nil, nil)
	reloadTestWrite(t, filepath.Join(dir, "..2026_02", "tls.crt"), third.certPEM)
	reloadTestWrite(t, filepath.Join(dir, "..2026_02", "tls.key"), third.keyPEM)
	reloadTestWantSerial(t, r, 3)
}

func TestTLSCertificateReloaderCloseStopsUpdates(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	original := reloadTestCertificate(t, 1, nil, nil)
	replacement := reloadTestCertificate(t, 2, nil, nil)
	reloadTestWrite(t, certFile, original.certPEM)
	reloadTestWrite(t, keyFile, original.keyPEM)
	r := reloadTestNewReloader(t, certFile, keyFile)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	previous, processed := r.certificate.Load(), r.processed.Load()
	reloadTestWrite(t, certFile, replacement.certPEM)
	reloadTestWrite(t, keyFile, replacement.keyPEM)
	// Give a running watcher enough time to receive and debounce this update.
	time.Sleep(300 * time.Millisecond)
	if r.processed.Load() != processed || r.certificate.Load() != previous {
		t.Fatal("closed certificate watcher processed an update")
	}
	// A TLS callback remains usable even when no certificate files exist. It
	// returns the cached pair without initiating another reload attempt.
	for _, path := range []string{certFile, keyFile} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	cert, err := r.getCertificate(&tls.ClientHelloInfo{})
	if err != nil || cert != previous || r.processed.Load() != processed {
		t.Fatalf("cached callback after file removal: certificate=%p want=%p err=%v", cert, previous, err)
	}
	reloadTestWantSerial(t, r, 1)
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
	r := reloadTestNewReloader(t, certFile, keyFile)
	previous, before := r.certificate.Load(), r.processed.Load()
	reloadTestWrite(t, certFile, invalidChain)
	if unexpected, err := newTLSCertificateReloader(certFile, keyFile); err == nil {
		_ = unexpected.Close()
		t.Fatal("chain signed by an unrelated CA accepted")
	}
	reloadTestWantFallback(t, r, before, previous)
	reloadTestWantSerial(t, r, 1)
}

func TestTLSCertificateReloaderConcurrentCallbacks(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	original := reloadTestCertificate(t, 1, nil, nil)
	replacement := reloadTestCertificate(t, 2, nil, nil)
	reloadTestWrite(t, certFile, original.certPEM)
	reloadTestWrite(t, keyFile, original.keyPEM)
	r := reloadTestNewReloader(t, certFile, keyFile)
	errors := make(chan error, 16)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var stopOnce sync.Once
	stopWorkers := func() {
		stopOnce.Do(func() { close(stop) })
		wg.Wait()
	}
	defer stopWorkers()
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
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
				time.Sleep(time.Millisecond)
			}
		}()
	}
	// Concurrent handshakes can observe missing or mismatched files during rotation,
	// but must always receive a complete, previously validated certificate.
	reloadTestWrite(t, certFile, replacement.certPEM)
	reloadTestWrite(t, keyFile, replacement.keyPEM)
	reloadTestWantSerial(t, r, 2)
	stopWorkers()
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
			r := reloadTestNewReloader(t, certFile, keyFile)
			previous, before := r.certificate.Load(), r.processed.Load()
			reloadTestWrite(t, certFile, tc.cert)
			reloadTestWrite(t, keyFile, tc.key)
			if unexpected, err := newTLSCertificateReloader(certFile, keyFile); err == nil {
				_ = unexpected.Close()
				t.Fatal("invalid certificate constraints accepted at startup")
			}
			reloadTestWantFallback(t, r, before, previous)
			reloadTestWantSerial(t, r, 1)
		})
	}
}
