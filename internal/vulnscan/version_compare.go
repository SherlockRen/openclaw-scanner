package vulnscan

import (
	"strconv"
	"strings"
)

func versionLessThan(current, baseline string) bool {
	if current == "" || baseline == "" {
		return false
	}
	ca := normalize(current)
	ba := normalize(baseline)
	n := len(ca)
	if len(ba) > n {
		n = len(ba)
	}
	for i := 0; i < n; i++ {
		cv := 0
		bv := 0
		if i < len(ca) {
			cv = ca[i]
		}
		if i < len(ba) {
			bv = ba[i]
		}
		if cv < bv {
			return true
		}
		if cv > bv {
			return false
		}
	}
	return false
}

func normalize(v string) []int {
	v = strings.TrimSpace(v)
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := ""
		for _, r := range p {
			if r >= '0' && r <= '9' {
				n += string(r)
			} else {
				break
			}
		}
		if n == "" {
			out = append(out, 0)
			continue
		}
		iv, err := strconv.Atoi(n)
		if err != nil {
			out = append(out, 0)
			continue
		}
		out = append(out, iv)
	}
	return out
}
