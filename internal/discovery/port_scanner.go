package discovery

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	naabuprotocol "github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"openclaw-scan/internal/models"
)

func DefaultPorts() []int {
	return []int{18789, 19001, 443, 80, 8080, 8443}
}

func ParsePorts(input string) ([]int, error) {
	parts := strings.Split(input, ",")
	out := make([]int, 0)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			r := strings.Split(part, "-")
			if len(r) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			a, err := strconv.Atoi(strings.TrimSpace(r[0]))
			if err != nil {
				return nil, err
			}
			b, err := strconv.Atoi(strings.TrimSpace(r[1]))
			if err != nil {
				return nil, err
			}
			for i := a; i <= b; i++ {
				out = append(out, i)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid ports")
	}
	return out, nil
}

func ParseTargets(input string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("target required")
	}
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		targets, err := parseTargetToken(p)
		if err != nil {
			return nil, err
		}
		for _, t := range targets {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("target required")
	}
	return out, nil
}

func parseTargetToken(token string) ([]string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("target required")
	}

	if strings.Contains(token, "://") {
		u, err := url.Parse(token)
		if err != nil {
			return nil, fmt.Errorf("invalid url target: %s", token)
		}
		host := strings.TrimSpace(u.Hostname())
		if host == "" {
			return nil, fmt.Errorf("invalid url target host: %s", token)
		}
		return []string{host}, nil
	}

	if strings.Contains(token, "/") {
		if _, _, err := net.ParseCIDR(token); err == nil {
			return expandCIDR(token)
		}
		u, err := url.Parse("http://" + token)
		if err == nil {
			host := strings.TrimSpace(u.Hostname())
			if host != "" {
				return []string{host}, nil
			}
		}
		return nil, fmt.Errorf("invalid target/cidr: %s", token)
	}

	if host, _, err := net.SplitHostPort(token); err == nil {
		host = strings.TrimSpace(host)
		if host == "" {
			return nil, fmt.Errorf("invalid host:port target: %s", token)
		}
		return []string{host}, nil
	}

	return []string{token}, nil
}

func ScanOpenPorts(targets []string, ports []int, threads int, timeout time.Duration) ([]models.HostScan, error) {
	if threads <= 0 {
		threads = 100
	}
	_ = naabuprotocol.TCP

	agg := map[string]*models.HostScan{}
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	sem := make(chan struct{}, threads)

	for _, host := range targets {
		for _, port := range ports {
			wg.Add(1)
			go func(host string, port int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				addr := net.JoinHostPort(host, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err != nil {
					return
				}
				_ = conn.Close()

				service, product, version := detectHTTPService(host, port, timeout)

				mu.Lock()
				hs, ok := agg[host]
				if !ok {
					hs = &models.HostScan{Target: host, OpenPorts: []int{}, Services: map[int]string{}, Products: map[int]string{}, Versions: map[int]string{}}
					agg[host] = hs
				}
				hs.OpenPorts = append(hs.OpenPorts, port)
				if service != "" {
					hs.Services[port] = service
				}
				if product != "" {
					hs.Products[port] = product
				}
				if version != "" {
					hs.Versions[port] = version
				}
				mu.Unlock()
			}(host, port)
		}
	}
	wg.Wait()

	out := make([]models.HostScan, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	return out, nil
}

func detectHTTPService(host string, port int, timeout time.Duration) (service, product, version string) {
	if port != 80 && port != 443 && port != 8080 && port != 8443 && port != 18789 && port != 19001 {
		return "", "", ""
	}
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	client := &net.Dialer{Timeout: timeout}
	_ = client
	url := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	httpClient := &nethttpClient{timeout: timeout}
	server := httpClient.serverHeader(url)
	if server == "" {
		return "http", "", ""
	}
	parts := strings.Split(server, "/")
	service = "http"
	product = strings.ToLower(strings.TrimSpace(parts[0]))
	if len(parts) > 1 {
		version = strings.TrimSpace(parts[1])
	}
	return service, product, version
}

type nethttpClient struct{ timeout time.Duration }

func (c *nethttpClient) serverHeader(url string) string {
	client := netHTTPClient(c.timeout)
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return strings.TrimSpace(resp.Header.Get("Server"))
}
