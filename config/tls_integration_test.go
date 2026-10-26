package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

type integrationTLSPair struct {
	certPEM, keyPEM []byte
}

func integrationTLSIssue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, client bool, expired bool) integrationTLSPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if expired {
		template.NotBefore = time.Now().Add(-2 * time.Hour)
		template.NotAfter = time.Now().Add(-time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return integrationTLSPair{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func integrationTLSWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	// Rename into place, as certificate renewal tools commonly do.
	if err := os.WriteFile(path+".new", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

func integrationTLSAwaitSerial(t *testing.T, reloader *tlsCertificateReloader, serial int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cert := reloader.certificate.Load()
		if cert != nil && cert.Leaf.SerialNumber.Int64() == serial {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("watcher did not publish certificate serial %d before a new handshake", serial)
}

func integrationTLSAwaitProcessed(t *testing.T, reloader *tlsCertificateReloader, previous uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if reloader.processed.Load() > previous {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("watcher did not process certificate update")
}

func TestTLSCertificateReloadListeners(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "reload test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	first := integrationTLSIssue(t, ca, caKey, 1, false, false)
	second := integrationTLSIssue(t, ca, caKey, 2, false, false)
	third := integrationTLSIssue(t, ca, caKey, 3, false, false)
	expired := integrationTLSIssue(t, ca, caKey, 4, false, true)
	clientPair := integrationTLSIssue(t, ca, caKey, 5, true, false)
	clientCert, err := tls.X509KeyPair(clientPair.certPEM, clientPair.keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	for _, mtls := range []bool{false, true} {
		t.Run(fmt.Sprintf("mTLS=%t", mtls), func(t *testing.T) {
			dir := t.TempDir()
			cfg := &Config{
				MinTLSVersion: "1.2",
				TLSCertFile:   filepath.Join(dir, "cert.pem"),
				TLSKeyFile:    filepath.Join(dir, "key.pem"),
			}
			integrationTLSWrite(t, cfg.TLSCertFile, first.certPEM)
			integrationTLSWrite(t, cfg.TLSKeyFile, first.keyPEM)
			clientTLS := &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
			if mtls {
				cfg.TLSCaFile = filepath.Join(dir, "ca.pem")
				integrationTLSWrite(t, cfg.TLSCaFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
				clientTLS.Certificates = []tls.Certificate{clientCert}
			}
			if err := cfg.setTLSConfig(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cfg.TLSCertificateWatcher.Close(); err != nil {
					t.Errorf("closing TLS certificate watcher: %v", err)
				}
			})
			reloader, ok := cfg.TLSCertificateWatcher.(*tlsCertificateReloader)
			if !ok {
				t.Fatal("missing TLS certificate watcher")
			}
			if cfg.TLSConfig.GetCertificate == nil || len(cfg.TLSConfig.Certificates) != 0 {
				t.Fatal("listeners must use GetCertificate, including connections without SNI")
			}
			if mtls && cfg.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven {
				t.Fatal("mTLS authentication policy changed")
			}

			httpListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			httpServer := &http.Server{TLSConfig: cfg.TLSConfig, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mtls && len(r.TLS.VerifiedChains) == 0 {
					http.Error(w, "client certificate required", http.StatusUnauthorized)
					return
				}
				_, _ = io.WriteString(w, "ok")
			})}
			httpDone := make(chan error, 1)
			go func() { httpDone <- httpServer.ServeTLS(httpListener, "", "") }()
			t.Cleanup(func() {
				_ = httpServer.Close()
				if err := <-httpDone; err != http.ErrServerClosed {
					t.Errorf("HTTPS listener failed: %v", err)
				}
			})

			grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg.TLSConfig)))
			grpc_health_v1.RegisterHealthServer(grpcServer, health.NewServer())
			grpcDone := make(chan error, 1)
			go func() { grpcDone <- grpcServer.Serve(grpcListener) }()
			t.Cleanup(func() {
				grpcServer.Stop()
				if err := <-grpcDone; err != nil {
					t.Errorf("gRPC listener failed: %v", err)
				}
			})

			check := func(wantSerial int64) {
				t.Helper()
				// IP ServerName verifies the IP SAN without sending SNI. New
				// connections ensure these checks cannot reuse old TLS sessions.
				transport := &http.Transport{TLSClientConfig: clientTLS.Clone(), DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				resp, err := httpClient.Get("https://" + httpListener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
					t.Fatalf("HTTPS request: status=%d body=%q err=%v", resp.StatusCode, body, err)
				}
				if got := resp.TLS.PeerCertificates[0].SerialNumber.Int64(); got != wantSerial {
					t.Fatalf("HTTPS certificate serial=%d, want %d", got, wantSerial)
				}

				conn, err := grpc.NewClient(grpcListener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS.Clone())))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var p peer.Peer
				response, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{}, grpc.Peer(&p))
				if err != nil {
					t.Fatal(err)
				}
				if response.Status != grpc_health_v1.HealthCheckResponse_SERVING {
					t.Fatalf("gRPC health status=%v", response.Status)
				}
				info, ok := p.AuthInfo.(credentials.TLSInfo)
				if !ok || len(info.State.PeerCertificates) == 0 {
					t.Fatal("missing gRPC TLS peer certificate")
				}
				if got := info.State.PeerCertificates[0].SerialNumber.Int64(); got != wantSerial {
					t.Fatalf("gRPC certificate serial=%d, want %d", got, wantSerial)
				}
			}

			check(1)
			processed := reloader.processed.Load()
			integrationTLSWrite(t, cfg.TLSCertFile, second.certPEM)
			integrationTLSAwaitProcessed(t, reloader, processed)
			check(1) // certificate/key update is incomplete
			integrationTLSWrite(t, cfg.TLSKeyFile, second.keyPEM)
			// Observe the new cached certificate before any callback/handshake:
			// publication must be driven by filesystem events, not new traffic.
			integrationTLSAwaitSerial(t, reloader, 2)
			check(2)
			processed = reloader.processed.Load()
			integrationTLSWrite(t, cfg.TLSCertFile, []byte("incomplete PEM"))
			integrationTLSAwaitProcessed(t, reloader, processed)
			check(2)
			processed = reloader.processed.Load()
			integrationTLSWrite(t, cfg.TLSCertFile, expired.certPEM)
			integrationTLSWrite(t, cfg.TLSKeyFile, expired.keyPEM)
			integrationTLSAwaitProcessed(t, reloader, processed)
			check(2)
			integrationTLSWrite(t, cfg.TLSCertFile, third.certPEM)
			integrationTLSWrite(t, cfg.TLSKeyFile, third.keyPEM)
			integrationTLSAwaitSerial(t, reloader, 3)
			check(3)
			if mtls {
				// A certificate signed by the trusted CA but intended only for
				// server authentication must still be rejected as a client cert.
				wrongPurpose, err := tls.X509KeyPair(second.certPEM, second.keyPEM)
				if err != nil {
					t.Fatal(err)
				}
				invalidClientTLS := clientTLS.Clone()
				invalidClientTLS.Certificates = nil
				invalidClientTLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &wrongPurpose, nil
				}
				transport := &http.Transport{TLSClientConfig: invalidClientTLS, DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				resp, err := client.Get("https://" + httpListener.Addr().String())
				if resp != nil {
					_ = resp.Body.Close()
				}
				if err == nil {
					t.Fatal("mTLS accepted a certificate without client authentication usage after rotation")
				}
			}
		})
	}
}
