package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// tlsServerWithExpiry serves a self-signed certificate valid for exactly the
// window given, so the expiry grading can be tested against a real handshake
// rather than a stubbed clock.
func tlsServerWithExpiry(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dc1.corp.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"dc1.corp.example.com", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				// Force the handshake, then hang up: the client only wants the
				// certificate, not a conversation.
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestInspectCertReadsExpiry(t *testing.T) {
	addr := tlsServerWithExpiry(t, time.Now().Add(-24*time.Hour), time.Now().Add(90*24*time.Hour))
	in := inspectCert(context.Background(), addr, 3*time.Second)
	if in.Err != "" {
		t.Fatal(in.Err)
	}
	if in.Subject != "dc1.corp.example.com" {
		t.Errorf("subject = %q", in.Subject)
	}
	if in.DaysLeft < 88 || in.DaysLeft > 90 {
		t.Errorf("days left = %d, want ~89", in.DaysLeft)
	}
	if !in.SelfSigned {
		t.Error("a self-signed cert was not flagged as such")
	}
	if in.Trusted {
		t.Error("a self-signed cert must not be reported as trusted")
	}
}

// An already-expired certificate is the case this tool exists to catch before
// it happens, so it must grade as broken, not merely noteworthy.
func TestExpiredCertIsAFailure(t *testing.T) {
	addr := tlsServerWithExpiry(t, time.Now().Add(-60*24*time.Hour), time.Now().Add(-5*24*time.Hour))
	in := inspectCert(context.Background(), addr, 3*time.Second)
	if in.Err != "" {
		t.Fatal(in.Err)
	}
	if in.DaysLeft > 0 {
		t.Fatalf("days left = %d, want negative", in.DaysLeft)
	}
	checks := certChecks([]certInfo{in}, 30)
	if checks[0].Status != StatusFail {
		t.Errorf("an expired certificate graded %v, want fail", checks[0].Status)
	}
	if !strings.Contains(checks[0].Summary, "EXPIRED") {
		t.Errorf("summary = %q, should say it has expired", checks[0].Summary)
	}
}

func TestCertExpiringSoonIsAFailure(t *testing.T) {
	addr := tlsServerWithExpiry(t, time.Now().Add(-24*time.Hour), time.Now().Add(9*24*time.Hour))
	checks := certChecks([]certInfo{inspectCert(context.Background(), addr, 3*time.Second)}, 30)
	if checks[0].Status != StatusFail {
		t.Errorf("a cert with 9 days left graded %v, want fail", checks[0].Status)
	}
	if checks[0].Advice == "" {
		t.Error("an expiring certificate must come with advice")
	}
}

// Sorting is the feature: soonest-to-expire first, with unreachable hosts last
// so they cannot bury a certificate that is about to take a service down.
func TestAuditSortsSoonestFirstAndErrorsLast(t *testing.T) {
	far := tlsServerWithExpiry(t, time.Now().Add(-time.Hour), time.Now().Add(300*24*time.Hour))
	near := tlsServerWithExpiry(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	dead := "127.0.0.1:1"

	got := auditCerts(context.Background(), []string{far, dead, near}, 4, 2*time.Second)
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}
	if got[0].Host != near {
		t.Errorf("first result is %s, want the soonest to expire", got[0].Host)
	}
	if got[1].Host != far {
		t.Errorf("second result is %s, want the later one", got[1].Host)
	}
	if got[2].Err == "" {
		t.Error("the unreachable host should sort last")
	}
}

func TestUnreachableHostIsReportedNotFatal(t *testing.T) {
	in := inspectCert(context.Background(), "127.0.0.1:1", 300*time.Millisecond)
	if in.Err == "" {
		t.Fatal("expected an error for a closed port")
	}
	c := certChecks([]certInfo{in}, 30)[0]
	if c.Status != StatusWarn {
		t.Errorf("status = %v, want warn", c.Status)
	}
}

// A plain host with no port must default to 443 rather than failing to parse.
func TestBareHostDefaultsTo443(t *testing.T) {
	in := inspectCert(context.Background(), "127.0.0.1", 200*time.Millisecond)
	if !strings.HasSuffix(in.Host, ":443") {
		t.Errorf("host = %q, want :443 appended", in.Host)
	}
}
