package discovery

import "net"

func ReverseDNS(ip string) []string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	return names
}
