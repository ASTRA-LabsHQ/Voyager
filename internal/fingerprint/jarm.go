package fingerprint

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	jarm "github.com/hdm/jarm-go"
	"golang.org/x/net/proxy"
)

// JARMFingerprinter fingerprints a target's TLS stack with JARM and checks
// the result against knownJARM. Dialer is expected to be a Tor SOCKS5
// dialer in production use, but any proxy.Dialer (including proxy.Direct)
// works — JARM only needs a raw, byte-transparent TCP tunnel to the target.
type JARMFingerprinter struct {
	Dialer  proxy.Dialer
	Timeout time.Duration
}

func NewJARMFingerprinter(dialer proxy.Dialer, timeout time.Duration) *JARMFingerprinter {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &JARMFingerprinter{Dialer: dialer, Timeout: timeout}
}

func (j *JARMFingerprinter) Name() string { return "jarm" }

// Fingerprint runs the 10-probe JARM handshake sequence against host:port
// and returns the resulting hash, independent of whether it matches
// anything known.
func (j *JARMFingerprinter) Fingerprint(ctx context.Context, host string, port int) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	results := make([]string, 0, 10)

	for _, probe := range jarm.GetProbes(host, port) {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		conn, err := j.Dialer.Dial("tcp", addr)
		if err != nil {
			results = append(results, "")
			continue
		}

		data := jarm.BuildProbe(probe)
		conn.SetWriteDeadline(time.Now().Add(j.Timeout))
		if _, err := conn.Write(data); err != nil {
			results = append(results, "")
			conn.Close()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(j.Timeout))
		buf := make([]byte, 1484)
		conn.Read(buf) //nolint:errcheck // matches upstream jarmscan: a short/failed read still yields a valid (empty) probe result
		conn.Close()

		ans, err := jarm.ParseServerHello(buf, probe)
		if err != nil {
			results = append(results, "")
			continue
		}
		results = append(results, ans)
	}

	return jarm.RawHashToFuzzyHash(strings.Join(results, ",")), nil
}

func (j *JARMFingerprinter) Detect(ctx context.Context, host string, port int) (Result, error) {
	hash, err := j.Fingerprint(ctx, host, port)
	if err != nil {
		return Result{}, fmt.Errorf("jarm: %w", err)
	}

	sigs, ok := knownJARM[hash]
	if !ok {
		return Result{Raw: hash}, nil
	}

	matches := make([]Match, 0, len(sigs))
	for _, sig := range sigs {
		note := "JARM fingerprints the TLS stack, not the application — corroborate before treating this as confirmed C2."
		if len(sigs) > 1 {
			note = "Multiple frameworks share this JARM hash (same underlying TLS runtime); " + note
		}
		matches = append(matches, Match{
			Framework: sig.Framework,
			Indicator: "JARM",
			Value:     hash,
			Note:      note,
			Source:    sig.Source,
		})
	}
	return Result{Raw: hash, Matches: matches}, nil
}
