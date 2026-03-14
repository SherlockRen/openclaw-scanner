package discovery

import (
	"fmt"
	"math/big"
	"net"
)

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only ipv4 cidr is supported currently")
	}
	maskSize, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only ipv4 cidr is supported currently")
	}
	hosts := 1 << (32 - maskSize)
	if hosts > 65536 {
		return nil, fmt.Errorf("cidr range too large")
	}
	base := big.NewInt(0).SetBytes(ip)
	out := make([]string, 0, hosts)
	for i := 0; i < hosts; i++ {
		cur := big.NewInt(0).Add(base, big.NewInt(int64(i))).Bytes()
		full := make([]byte, 4)
		copy(full[4-len(cur):], cur)
		out = append(out, net.IP(full).String())
	}
	return out, nil
}
