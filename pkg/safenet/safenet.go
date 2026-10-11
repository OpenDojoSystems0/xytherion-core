package safenet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

var privateNetworks []*net.IPNet

func init() {
	blocks := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"::1/128",        // IPv6 loopback
		"169.254.0.0/16", // link-local / cloud metadata
		"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // RFC-1918
		"172.16.0.0/12",  // RFC-1918
		"192.168.0.0/16", // RFC-1918
		"100.64.0.0/10",  // CGNAT (RFC 6598)
		"fc00::/7",       // IPv6 ULA
		"0.0.0.0/8",      // "this" network
	}
	for _, b := range blocks {
		_, n, err := net.ParseCIDR(b)
		if err == nil {
			privateNetworks = append(privateNetworks, n)
		}
	}
}

// IsPrivateIP returns true if ip is loopback, link-local, or in a private/reserved range.
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range privateNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateURL returns true if the URL's host is or DNS-resolves to a private/reserved IP.
// Performs a DNS lookup to prevent DNS rebinding attacks.
func IsPrivateURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return IsPrivateIP(ip)
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return true // unresolvable — block to avoid targeting internal DNS-only hosts
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && IsPrivateIP(ip) {
			return true
		}
	}
	return false
}

// Transport returns an http.RoundTripper that re-validates the resolved IP at dial time,
// preventing TOCTOU races between the initial URL check and the actual TCP connection.
func Transport() *http.Transport {
	return &http.Transport{
		DialContext:           dialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("safenet: DNS lookup failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("safenet: no addresses resolved for %s", host)
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil && IsPrivateIP(ip) {
			return nil, fmt.Errorf("safenet: connection to private/reserved address blocked: %s", ipStr)
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	// Connect directly to the first resolved IP to pin the address.
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
}
