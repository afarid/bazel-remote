package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func (c *Config) setTLSConfig() error {

	supportedTLSServerVersions := map[string]uint16{
		"1.0": tls.VersionTLS10,
		"1.1": tls.VersionTLS11,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}

	minTLSVersion, ok := supportedTLSServerVersions[c.MinTLSVersion]
	if !ok {
		return errors.New("Unsupported min_tls_version: \"" + c.MinTLSVersion + "\", must be one of 1.0, 1.1, 1.2, 1.3.")
	}

	if c.TLSCertFile == "" && c.TLSKeyFile == "" && c.TLSCaFile == "" {
		return nil
	}

	reloader, err := newTLSCertificateReloader(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		// Leave Certificates empty so even clients without SNI use the callback.
		GetCertificate: reloader.getCertificate,
		MinVersion:     minTLSVersion,
	}

	if len(c.TLSCaFile) != 0 {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(c.TLSCaFile)
		if err != nil {
			return fmt.Errorf("error reading TLS CA File: %w", err)
		}
		added := caCertPool.AppendCertsFromPEM(caCert)
		if !added {
			return fmt.Errorf("failed to add certificate to cert pool")
		}

		tlsConfig.ClientCAs = caCertPool
		// This allows us to handle some requests without a valid client
		// certificate (like the grpc health check service), but then we
		// need to explicitly check for verified certs on requests that
		// we require auth for.
		// See server.checkGRPCClientCert and httpCache.hasValidClientCert.
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	c.TLSConfig = tlsConfig
	return nil
}
