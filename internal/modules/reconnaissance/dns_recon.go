package reconnaissance

import (
	"net"
)

type DNSReconResult struct {
	Records map[string][]string
}

func DNSRecon(target string) (*DNSReconResult, error) {
	result := &DNSReconResult{Records: make(map[string][]string)}
	recordTypes := []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME"}
	for _, rtype := range recordTypes {
		rrs, err := net.LookupHost(target)
		if err == nil {
			result.Records[rtype] = rrs
		}
	}
	return result, nil
}
