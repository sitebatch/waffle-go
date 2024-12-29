package ssrf

import (
	"fmt"
	"net"
	"net/url"
)

var (
	metadataServiceEndpointHosts = []string{
		"metadata.google.internal",
		"169.254.169.254",
	}

	metadataServiceEndpointCIDRs = []string{
		"169.254.0.0/16",
		"fe80::/10",
	}
)

func IsCloudMetadataServiceURL(u string) error {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL: %s", err)
	}

	hostname := parsedURL.Hostname()

	for _, h := range metadataServiceEndpointHosts {
		if hostname == h {
			return fmt.Errorf("cloud metadata service URL detected: %s", u)
		}
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return fmt.Errorf("resolution error: %s", err)
	}

	for _, addr := range addrs {
		for _, cidr := range metadataServiceEndpointCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("invalid CIDR: %s", err)
			}

			if ipNet.Contains(net.ParseIP(addr)) {
				return fmt.Errorf("cloud metadata service URL detected: %s", u)
			}
		}
	}

	return nil
}
