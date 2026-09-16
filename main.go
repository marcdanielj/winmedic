// winmedic diagnoses the things that actually break Windows environments, and
// says what to do about each one in plain language.
//
// It is a single executable with no installer and no dependencies, because the
// machine that needs diagnosing is rarely in a state to install anything.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "winmedic:", err)
		os.Exit(3)
	}
	os.Exit(code)
}

func run() (int, error) {
	if len(os.Args) < 2 {
		usage()
		return 3, fmt.Errorf("need a subcommand")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch os.Args[1] {
	case "ad", "domain":
		return cmdAD(ctx, os.Args[2:])
	case "boot":
		return cmdBoot(ctx, os.Args[2:])
	case "certs":
		return cmdCerts(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return 0, nil
	default:
		usage()
		return 3, fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
}

// cmdAD answers "why can this PC not sign in or reach the shared drive".
func cmdAD(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("ad", flag.ExitOnError)
	domain := fs.String("domain", "", "AD domain, e.g. corp.example.com (default: detect)")
	dc := fs.String("dc", "", "test this domain controller instead of discovering one")
	timeout := fs.Duration("timeout", 3*time.Second, "per-check timeout")
	asJSON := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(args)

	if *domain == "" {
		*domain = guessDomain()
	}
	if *domain == "" && *dc == "" {
		return 3, fmt.Errorf("could not detect the domain; pass -domain corp.example.com (or -dc)")
	}

	rep := Report{Target: *domain}
	target := *dc

	// Discovery is first because it is both the most common failure and a
	// prerequisite for everything after it: without a domain controller to aim
	// at, the remaining checks have no subject.
	if target == "" {
		hosts, c := discoverDCs(ctx, net.DefaultResolver, *domain)
		rep.Checks = append(rep.Checks, c)
		if len(hosts) == 0 {
			return finish(rep, *asJSON), nil
		}
		target = hosts[0]
	} else {
		rep.Checks = append(rep.Checks, ok("dns", "skipped discovery, using "+target))
	}
	rep.Target = target

	rep.Checks = append(rep.Checks,
		checkClock(target, *timeout),
		checkPorts(ctx, target, adPorts, *timeout),
		checkLDAPSCert(ctx, target, *timeout),
	)
	return finish(rep, *asJSON), nil
}

// cmdBoot answers "why does this PC take so long to start".
func cmdBoot(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("boot", flag.ExitOnError)
	count := fs.Int("n", 10, "how many recent boots to read")
	show := fs.Int("show", 5, "how many rows to print")
	from := fs.String("from", "", "read wevtutil XML from a file instead of the live log")
	asJSON := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(args)

	var raw string
	if *from != "" {
		// Reading a saved export is how this gets used in practice: the person
		// with the broken PC runs wevtutil, sends you the XML, and you look at
		// it from whatever machine you happen to have.
		b, err := os.ReadFile(*from)
		if err != nil {
			return 3, err
		}
		raw = string(b)
	} else {
		var err error
		raw, err = readBootLog(ctx, *count)
		if err != nil {
			rep := Report{Checks: []Check{skip("boot", err.Error())}}
			if !*asJSON {
				fmt.Println("\n  The boot log lives on the Windows machine. To look at one from here:")
				fmt.Printf("    wevtutil qe %s /q:\"*[System[(EventID=100)]]\" /f:xml /c:10 > boot.xml\n", bootChannel)
				fmt.Println("    winmedic boot -from boot.xml")
			}
			return finish(rep, *asJSON), nil
		}
	}

	boots, culprits, err := parseBootEvents(strings.NewReader(raw))
	if err != nil {
		return 3, fmt.Errorf("reading the boot log: %w", err)
	}
	rep := Report{Target: "startup", Checks: bootChecks(boots, culprits, *show)}
	return finish(rep, *asJSON), nil
}

// cmdCerts answers "what is about to expire and take something down with it".
func cmdCerts(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("certs", flag.ExitOnError)
	file := fs.String("f", "", "file of host:port lines (# comments allowed)")
	warnDays := fs.Int("days", 30, "flag anything expiring within this many days")
	workers := fs.Int("workers", 32, "how many hosts to check at once")
	timeout := fs.Duration("timeout", 5*time.Second, "per-host timeout")
	asJSON := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(args)

	targets := fs.Args()
	if *file != "" {
		fromFile, err := readTargets(*file)
		if err != nil {
			return 3, err
		}
		targets = append(targets, fromFile...)
	}
	if len(targets) == 0 {
		return 3, fmt.Errorf("give hosts as arguments, or -f a file of them")
	}

	infos := auditCerts(ctx, targets, *workers, *timeout)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(infos); err != nil {
			return 3, err
		}
		return Report{Checks: certChecks(infos, *warnDays)}.ExitCode(), nil
	}
	rep := Report{Target: fmt.Sprintf("%d endpoints", len(targets)), Checks: certChecks(infos, *warnDays)}
	return finish(rep, false), nil
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// finish renders a report and returns the process exit code, so this can be
// wired into a monitoring script as easily as it is read by a person.
func finish(rep Report, asJSON bool) int {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		rep.Write(os.Stdout)
	}
	return rep.ExitCode()
}

func usage() {
	fmt.Fprint(os.Stderr, `winmedic - diagnose the things that actually break Windows environments

One executable, no installer, no dependencies. Exit code is 0 healthy,
1 needs attention, 2 broken - so it scripts as well as it reads.

  winmedic ad       why this PC cannot sign in or reach the shared drive
  winmedic boot     why this PC takes so long to start
  winmedic certs    what is about to expire and take something down with it

examples:
  winmedic ad                              detect the domain and check it
  winmedic ad -domain corp.example.com
  winmedic ad -dc dc1.corp.example.com

  winmedic boot                            read this PC's startup history
  winmedic boot -from boot.xml             read an export from another PC

  winmedic certs dc1.corp.example.com:636 intranet:443
  winmedic certs -f servers.txt -days 45

Every failure says what it breaks and what to do about it.
`)
}
