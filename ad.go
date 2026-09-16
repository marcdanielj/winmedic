package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// resolver is the slice of net.Resolver this tool uses, named so tests can
// supply their own answers instead of depending on whatever DNS the machine
// running the tests happens to have.
type resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// adPort is one port Active Directory needs, and what a user loses without it.
// The consequence is the point: "445 is closed" means nothing to most people,
// "file shares and group policy will not work" means everything.
type adPort struct {
	port     uint16
	name     string
	breaks   string
	optional bool
}

var adPorts = []adPort{
	{53, "DNS", "finding the domain at all", false},
	{88, "Kerberos", "signing in", false},
	{135, "RPC", "remote management and some group policy", false},
	{389, "LDAP", "reading the directory", false},
	{445, "SMB", "file shares and group policy delivery", false},
	{464, "kpasswd", "changing passwords", true},
	{636, "LDAPS", "encrypted directory lookups", true},
	{3268, "Global Catalog", "searching across the whole forest", true},
}

// discoverDCs finds domain controllers the way Windows does: by asking DNS for
// the service records the domain publishes.
//
// This is the step people skip when troubleshooting, and it is usually the
// answer. Active Directory is built on DNS - a machine that is asking a home
// router or a public resolver where the domain lives will never find it, no
// matter how healthy the network is otherwise.
func discoverDCs(ctx context.Context, r resolver, domain string) ([]string, Check) {
	const name = "dns"
	_, recs, err := r.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
	if err != nil || len(recs) == 0 {
		advice := "This PC is asking a DNS server that does not know about your domain -\n" +
			"usually a home router or a public resolver like 8.8.8.8.\n" +
			"Fix: set DNS to a domain controller's address, then:\n" +
			"  ipconfig /flushdns\n" +
			"  ipconfig /registerdns"
		detail := fmt.Sprintf("looked up _ldap._tcp.dc._msdcs.%s", domain)
		if err != nil {
			return nil, fail(name, "cannot find any domain controller in DNS", advice, detail, err.Error())
		}
		return nil, fail(name, "DNS answered, but listed no domain controllers", advice, detail)
	}

	// Lowest priority first, which is the order a client would try them.
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Priority < recs[j].Priority })
	hosts := make([]string, 0, len(recs))
	detail := make([]string, 0, len(recs))
	for _, rec := range recs {
		h := strings.TrimSuffix(rec.Target, ".")
		hosts = append(hosts, h)
		detail = append(detail, fmt.Sprintf("%s:%d (priority %d, weight %d)", h, rec.Port, rec.Priority, rec.Weight))
	}
	return hosts, ok(name, fmt.Sprintf("found %d domain controller(s) via DNS", len(hosts)), detail...)
}

// checkPorts dials every port AD needs, concurrently, and reports what a
// blocked one costs the user.
//
// The port list is a parameter rather than a global so tests can bind real
// listeners on ports they are allowed to bind - the well-known AD ports are all
// privileged, and a check that can only ever be tested in its failure case is
// half a check.
func checkPorts(ctx context.Context, host string, ports []adPort, timeout time.Duration) Check {
	const name = "ports"
	type outcome struct {
		p    adPort
		open bool
	}

	results := make([]outcome, len(ports))
	var wg sync.WaitGroup
	for i, p := range ports {
		wg.Add(1)
		go func(i int, p adPort) {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(p.port)))
			if err == nil {
				conn.Close()
			}
			results[i] = outcome{p, err == nil}
		}(i, p)
	}
	wg.Wait()

	var blocked, blockedOptional []outcome
	var detail []string
	for _, r := range results {
		state := "open"
		if !r.open {
			state = "BLOCKED"
			if r.p.optional {
				blockedOptional = append(blockedOptional, r)
			} else {
				blocked = append(blocked, r)
			}
		}
		detail = append(detail, fmt.Sprintf("%-5d %-15s %s", r.p.port, r.p.name, state))
	}

	switch {
	case len(blocked) > 0:
		var lines []string
		for _, b := range blocked {
			lines = append(lines, fmt.Sprintf("%d (%s) is blocked, so %s will not work", b.p.port, b.p.name, b.p.breaks))
		}
		lines = append(lines, "Usually a firewall, a VPN that is not connected, or a guest network.")
		return fail(name, fmt.Sprintf("%d required port(s) blocked on %s", len(blocked), host),
			strings.Join(lines, "\n"), detail...)
	case len(blockedOptional) > 0:
		var lines []string
		for _, b := range blockedOptional {
			lines = append(lines, fmt.Sprintf("%d (%s) is blocked, so %s will not work", b.p.port, b.p.name, b.p.breaks))
		}
		lines = append(lines, "Sign-in should still work; these are not needed by every environment.")
		return warn(name, "core ports open, some optional ones blocked", strings.Join(lines, "\n"), detail...)
	default:
		return ok(name, fmt.Sprintf("all %d ports reachable on %s", len(ports), host), detail...)
	}
}

// checkLDAPSCert reports on the certificate the directory presents.
//
// Verification is performed against the system roots, but a failure is reported
// rather than fatal: an internal CA that this machine does not trust is a real
// and common finding, and saying so is more useful than refusing to look.
func checkLDAPSCert(ctx context.Context, host string, timeout time.Duration) Check {
	const name = "certs"
	in := inspectCert(ctx, net.JoinHostPort(host, "636"), timeout)
	if in.Err != "" {
		if strings.HasPrefix(in.Err, "cannot connect") {
			return skip(name, "LDAPS (636) not reachable, nothing to inspect")
		}
		return warn(name, "LDAPS port is open but the certificate could not be read",
			"The service may not be LDAPS, or it requires a client certificate.", in.Err)
	}

	detail := []string{
		"subject " + orDash(in.Subject),
		"issuer  " + orDash(in.Issuer),
		"expires " + in.NotAfter.Format("2006-01-02"),
	}
	switch {
	case in.DaysLeft <= 0:
		return fail(name, fmt.Sprintf("the directory's certificate expired %d days ago", -in.DaysLeft),
			"Encrypted lookups fail and some clients refuse to sign in.\nRenew the certificate on the domain controller.", detail...)
	case in.DaysLeft <= 14:
		return fail(name, fmt.Sprintf("certificate expires in %d days", in.DaysLeft),
			"Renew it now. When it lapses, LDAPS stops working with no warning.", detail...)
	case in.DaysLeft <= 30:
		return warn(name, fmt.Sprintf("certificate expires in %d days", in.DaysLeft),
			"Schedule the renewal before it becomes an outage.", detail...)
	case !in.Trusted:
		return warn(name, "certificate is valid but this PC does not trust it",
			"Normal for an internal CA that has not been distributed to this machine.\n"+
				"Deploy the root CA via group policy, or import it locally.",
			append(detail, in.TrustErr)...)
	default:
		return ok(name, fmt.Sprintf("valid for %d more days, trusted", in.DaysLeft), detail...)
	}
}

// guessDomain finds the AD domain without being told, where the OS will say.
func guessDomain() string {
	// Windows sets this for any domain-joined session, which covers the case
	// this tool is actually run in.
	if d := os.Getenv("USERDNSDOMAIN"); d != "" {
		return strings.ToLower(d)
	}
	return ""
}
