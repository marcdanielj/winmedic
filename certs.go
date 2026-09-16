package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// certInfo is what one TLS endpoint presented. Shared by the Active Directory
// check and the fleet audit so there is exactly one piece of code that knows
// how to read a certificate off the wire.
type certInfo struct {
	Host       string    `json:"host"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"`
	TLSVersion string    `json:"tls_version"`
	SelfSigned bool      `json:"self_signed"`
	Trusted    bool      `json:"trusted"`
	TrustErr   string    `json:"trust_error,omitempty"`
	SANs       []string  `json:"sans,omitempty"`
	Err        string    `json:"error,omitempty"`
}

// inspectCert completes a TLS handshake and reads the certificate.
//
// The handshake deliberately skips Go's built-in verification and then verifies
// explicitly afterwards. Letting the handshake fail on an untrusted chain would
// throw away the certificate along with it - and "issued by a CA this machine
// does not trust" is a finding worth reporting, not a reason to go blind.
func inspectCert(ctx context.Context, target string, timeout time.Duration) certInfo {
	info := certInfo{Host: target}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
		info.Host = net.JoinHostPort(host, port)
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		info.Err = "cannot connect: " + err.Error()
		return info
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	c := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true}) //nolint:gosec // verified explicitly below
	if err := c.HandshakeContext(ctx); err != nil {
		info.Err = "TLS handshake failed: " + err.Error()
		return info
	}
	st := c.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		info.Err = "no certificate presented"
		return info
	}

	leaf := st.PeerCertificates[0]
	info.Subject = leaf.Subject.CommonName
	info.Issuer = leaf.Issuer.CommonName
	info.NotAfter = leaf.NotAfter
	info.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	info.TLSVersion = tlsVersionName(st.Version)
	info.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()
	info.SANs = leaf.DNSNames

	roots, _ := x509.SystemCertPool()
	inter := x509.NewCertPool()
	for _, ic := range st.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter}); err != nil {
		info.TrustErr = err.Error()
	} else {
		info.Trusted = true
	}
	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("TLS(0x%04x)", v)
}

// auditCerts inspects many endpoints at once and returns them worst-first,
// which for certificates means soonest to expire.
func auditCerts(ctx context.Context, targets []string, workers int, timeout time.Duration) []certInfo {
	if workers < 1 {
		workers = 1
	}
	out := make([]certInfo, len(targets))
	jobs := make(chan int)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				out[idx] = inspectCert(ctx, targets[idx], timeout)
			}
		}()
	}
	for i := range targets {
		select {
		case jobs <- i:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()

	slices.SortStableFunc(out, func(a, b certInfo) int {
		// Unreachable hosts sort last: they are a different problem from a
		// certificate about to lapse, and burying the expiring ones under them
		// would defeat the point of the ordering.
		if (a.Err != "") != (b.Err != "") {
			if a.Err != "" {
				return 1
			}
			return -1
		}
		return a.DaysLeft - b.DaysLeft
	})
	return out
}

// certChecks converts an audit into pass/fail rows.
func certChecks(infos []certInfo, warnDays int) []Check {
	checks := make([]Check, 0, len(infos))
	for _, in := range infos {
		if in.Err != "" {
			checks = append(checks, warn(in.Host, in.Err, "Check the host is up and the port is right."))
			continue
		}
		detail := []string{
			fmt.Sprintf("issuer %s · %s", orDash(in.Issuer), in.TLSVersion),
			"expires " + in.NotAfter.Format("2006-01-02"),
		}
		if len(in.SANs) > 0 {
			detail = append(detail, "names "+strings.Join(truncateList(in.SANs, 4), ", "))
		}

		switch {
		case in.DaysLeft <= 0:
			checks = append(checks, fail(in.Host, fmt.Sprintf("EXPIRED %d days ago", -in.DaysLeft),
				"This is breaking right now. Renew it.", detail...))
		case in.DaysLeft <= warnDays:
			checks = append(checks, fail(in.Host, fmt.Sprintf("expires in %d days", in.DaysLeft),
				"Renew before it lapses - expiry causes an outage with no warning.", detail...))
		case !in.Trusted && in.SelfSigned:
			checks = append(checks, warn(in.Host, fmt.Sprintf("self-signed, %d days left", in.DaysLeft),
				"Fine internally if intended; browsers and clients will warn.", detail...))
		case !in.Trusted:
			checks = append(checks, warn(in.Host, fmt.Sprintf("not trusted by this PC, %d days left", in.DaysLeft),
				"Usually an internal CA that has not been deployed here.\nDistribute the root CA via group policy.",
				append(detail, in.TrustErr)...))
		default:
			checks = append(checks, ok(in.Host, fmt.Sprintf("valid %d more days, trusted", in.DaysLeft), detail...))
		}
	}
	return checks
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncateList(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return append(slices.Clone(xs[:n]), fmt.Sprintf("+%d more", len(xs)-n))
}
