package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// LoadOrGenerateCert returns a TLS certificate, generating a self-signed one
// when configured and no files are supplied. The SHA256 fingerprint of the
// leaf DER is returned for client pinning.
func LoadOrGenerateCert(certFile, keyFile string, names []string) (tls.Certificate, string, error) {
	if certFile != "" && keyFile != "" {
		if _, e1 := os.Stat(certFile); e1 == nil {
			if _, e2 := os.Stat(keyFile); e2 == nil {
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					return tls.Certificate{}, "", err
				}
				fp := sha256.Sum256(cert.Certificate[0])
				return cert, hex.EncodeToString(fp[:]), nil
			}
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: firstNonEmpty(names, "c2v2-local")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, n := range names {
		if n != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	tmpl.DNSNames = append(tmpl.DNSNames, "localhost")
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if certFile != "" && keyFile != "" {
		// Persist the generated pair so the pin stays stable across restarts.
		if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err == nil {
			_ = os.WriteFile(certFile, certPEM, 0o600)
		} else {
			_ = os.WriteFile(certFile, certPEM, 0o600)
		}
		_ = os.WriteFile(keyFile, keyPEM, 0o600)
	}
	if os.Getenv("C2V2_DUMP_CERT") != "" {
		_ = os.WriteFile("generated-cert.pem", certPEM, 0600)
		_ = os.WriteFile("generated-key.pem", keyPEM, 0600)
	}
	fp := sha256.Sum256(der)
	return cert, hex.EncodeToString(fp[:]), nil
}

func firstNonEmpty(xs []string, def string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return def
}

// TLSConfig builds a server TLS config limited to 1.2/1.3.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}

func fingerprintOf(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	fp := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(fp[:])
}

func describeCert(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return "no-cert"
	}
	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "unparsable"
	}
	return fmt.Sprintf("CN=%s fp=%s", c.Subject.CommonName, fingerprintOf(cert))
}
