/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package pki issues the small private CA the mailnite<->relay tunnel trusts.
// The model is deliberately closed-world: one CA, created on the mailnite side
// during onboarding, signs exactly two leaf certificates —
//
//   - the relay SERVER cert (presented by the relay on the VDS), and
//   - the mailnite CLIENT cert (presented by mailnite when it dials in).
//
// Both ends are configured with the CA only, so each trusts the other and
// nothing else on the internet: the relay accepts a connection only from a
// client whose cert chains to this CA, and mailnite talks only to a relay whose
// cert does. That is the mutual-TLS floor for the tls:// and quic:// transports.
// Certs are ECDSA P-256 so the TLS 1.2 floor value-rpc uses is satisfied
// (Ed25519 would force TLS 1.3 only).
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"golang.org/x/xerrors"
)

// CA is a generated certificate authority: the parsed cert/key plus their PEM
// encodings (what onboarding stores and the deploy ships to the VDS).
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// Keypair is an issued leaf certificate and its private key, PEM-encoded.
type Keypair struct {
	CertPEM []byte
	KeyPEM  []byte
}

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 5 * 365 * 24 * time.Hour
)

// GenerateCA creates a new self-signed CA with the given common name.
func GenerateCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf("ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Mailnite Relay"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, xerrors.Errorf("ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return nil, err
	}
	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  keyPEM,
	}, nil
}

// LoadCA parses a CA from its PEM cert and key (as produced by GenerateCA).
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// IssueServerCert issues the relay's server certificate for the given hosts
// (DNS names and/or IP addresses the relay is reachable at). ExtKeyUsage is
// ServerAuth so a client's cert-verify accepts it as a server.
func (ca *CA) IssueServerCert(hosts []string) (*Keypair, error) {
	return ca.issue("mailrelay-server", hosts, x509.ExtKeyUsageServerAuth)
}

// IssueClientCert issues the mailnite client certificate. ExtKeyUsage is
// ClientAuth so the relay's RequireAndVerifyClientCert accepts it.
func (ca *CA) IssueClientCert(commonName string) (*Keypair, error) {
	return ca.issue(commonName, nil, x509.ExtKeyUsageClientAuth)
}

func (ca *CA) issue(commonName string, hosts []string, eku x509.ExtKeyUsage) (*Keypair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf("leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Mailnite Relay"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, xerrors.Errorf("sign leaf: %w", err)
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return nil, err
	}
	return &Keypair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  keyPEM,
	}, nil
}

// GenerateSelfSigned issues a standalone self-signed server certificate (its own
// issuer, no CA) for the key-authenticated relay mode: clients present a shared
// token for authentication and TLS provides the transport encryption. The cert's
// SANs don't need to match, since a token-mode client doesn't verify the chain —
// the mail protocols keep their own end-to-end TLS through the tunnel regardless.
func GenerateSelfSigned(hosts []string) (*Keypair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf("self-signed key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mailrelay", Organization: []string{"Mailnite Relay"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, xerrors.Errorf("self-signed cert: %w", err)
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return nil, err
	}
	return &Keypair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  keyPEM,
	}, nil
}

// ServerTLSConfig builds the relay's *tls.Config from its cert/key. When a CA is
// supplied it requires and verifies a client certificate chaining to that CA —
// the mutual-TLS enforcement for tls:// and quic://. Pass caPEM=nil for wss,
// where the client is authenticated by the handshake token instead.
func ServerTLSConfig(certPEM, keyPEM, caPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, xerrors.Errorf("relay keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, xerrors.New("CA PEM has no certificates")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ClientTLSConfig builds mailnite's *tls.Config: it trusts only the relay CA and
// presents the mailnite client certificate. serverName is matched against the
// relay cert's SANs (pass the host mailnite dials).
func ClientTLSConfig(caPEM, clientCertPEM, clientKeyPEM []byte, serverName string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, xerrors.New("CA PEM has no certificates")
	}
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, xerrors.Errorf("client keypair: %w", err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// RandomToken returns a URL-safe 256-bit secret for the ws handshake-token auth.
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, xerrors.Errorf("serial: %w", err)
	}
	return serial, nil
}

func marshalKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return nil, xerrors.New("no PEM certificate block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func parseKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, xerrors.New("no PEM key block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, xerrors.New("CA key is not ECDSA")
	}
	return ec, nil
}
