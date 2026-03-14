package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"openclaw-scan/internal/discovery"
	"openclaw-scan/internal/models"
	"openclaw-scan/internal/output"
	"openclaw-scan/internal/vulnscan"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: clawscanner <target|cidr> [--ports 18789,8080,3000] [--threads 100] [--timeout 30] [-o results.json]")
	}

	started := time.Now()
	target := args[0]
	fs := flag.NewFlagSet("clawscanner", flag.ContinueOnError)
	portsArg := fs.String("ports", "", "custom ports list/range")
	threads := fs.Int("threads", 100, "concurrency for probing")
	timeoutSec := fs.Int("timeout", 30, "timeout in seconds")
	outFile := fs.String("o", "", "json report output path")
	quiet := fs.Bool("quiet", false, "disable process logs")
	requester := fs.String("requester", "cli", "requester")
	scope := fs.String("scope", target, "authorization scope")
	timeWindow := fs.String("time-window", "now", "authorization time window")
	source := fs.String("source", "manual", "authorization source")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if !*quiet {
		printBanner()
	}

	a := models.Authorization{Requester: *requester, Scope: *scope, TimeWindow: *timeWindow, Source: *source}
	logStep(*quiet, "Authorization", "validating authorization fields")
	if err := vulnscan.ValidateAuthorization(a); err != nil {
		return err
	}

	parseStart := time.Now()
	logStep(*quiet, "Targets", "normalizing target input")
	targets, err := discovery.ParseTargets(target)
	if err != nil {
		return err
	}
	logDone(*quiet, "Targets", fmt.Sprintf("resolved %d target(s) in %s", len(targets), time.Since(parseStart).Truncate(time.Millisecond)))
	if !*quiet && len(targets) >= 128 && *timeoutSec > 5 {
		fmt.Printf("\x1b[33m[Hint       ]\x1b[0m large CIDR + timeout=%ds may be slow, try --timeout=1~3 or higher --threads\n", *timeoutSec)
	}

	ports := discovery.DefaultPorts()
	if *portsArg != "" {
		logStep(*quiet, "Ports", "parsing custom ports")
		ports, err = discovery.ParsePorts(*portsArg)
		if err != nil {
			return err
		}
	}
	if *portsArg == "" {
		logStep(*quiet, "Ports", "using default ports")
	}
	logDone(*quiet, "Ports", fmt.Sprintf("%s", intsToCSV(ports)))

	scanStart := time.Now()
	logStep(*quiet, "Scan", fmt.Sprintf("probing %d target(s) x %d port(s), threads=%d timeout=%ds", len(targets), len(ports), *threads, *timeoutSec))
	hosts, err := discovery.ScanOpenPorts(targets, ports, *threads, time.Duration(*timeoutSec)*time.Second)
	if err != nil {
		return err
	}
	logDone(*quiet, "Scan", fmt.Sprintf("found %d responsive host(s) in %s", len(hosts), time.Since(scanStart).Truncate(time.Millisecond)))

	detectStart := time.Now()
	logStep(*quiet, "Detect", "running OpenClaw fingerprint + vuln/path checks on open ports only")
	findings := make([]models.Finding, 0)
	for _, h := range hosts {
		if len(h.OpenPorts) == 0 {
			continue
		}
		findings = append(findings, discovery.DetectOpenClawFingerprint(h.Target, h.OpenPorts)...)
		findings = append(findings, vulnscan.DetectVersionVulns(h)...)
		findings = append(findings, vulnscan.DetectPathLeaks(h.Target, h.OpenPorts, 3*time.Second)...)
	}
	findings = normalizeFindings(findings)
	logDone(*quiet, "Detect", fmt.Sprintf("generated %d finding(s) in %s", len(findings), time.Since(detectStart).Truncate(time.Millisecond)))

	reportData := models.Report{
		SchemaVersion: "1.0",
		TaskMeta: models.TaskMeta{
			TaskID:      fmt.Sprintf("task-%d", time.Now().UnixNano()),
			StartedAt:   time.Now().Format(time.RFC3339),
			EndedAt:     time.Now().Format(time.RFC3339),
			Status:      "completed",
			TargetCount: len(targets),
			PortCount:   len(ports),
		},
		Summary: models.Summary{
			FindingCount: len(findings),
		},
		Findings: findings,
	}

	if !*quiet {
		printSummary(targets, ports, hosts, findings, time.Since(started).Truncate(time.Millisecond), *outFile)
	}
	return output.WriteJSON(reportData, *outFile)
}

func logStep(quiet bool, stage, msg string) {
	if quiet {
		return
	}
	fmt.Printf("\x1b[36m[%-12s]\x1b[0m %s\n", stage, msg)
}

func logDone(quiet bool, stage, msg string) {
	if quiet {
		return
	}
	fmt.Printf("\x1b[32m[%-12s]\x1b[0m ✓ %s\n", stage, msg)
}

func printSummary(targets []string, ports []int, hosts []models.HostScan, findings []models.Finding, elapsed time.Duration, outFile string) {
	hostPortCount := 0
	for _, h := range hosts {
		hostPortCount += len(h.OpenPorts)
	}

	fmt.Println()
	fmt.Println("\x1b[1;34m+----------------------+--------------------------------------+\x1b[0m")
	fmt.Printf("\x1b[1;34m| %-20s | %-36s |\x1b[0m\n", "Metric", "Value")
	fmt.Println("\x1b[1;34m+----------------------+--------------------------------------+\x1b[0m")
	fmt.Printf("| %-20s | %-36s |\n", "Targets", strconv.Itoa(len(targets)))
	fmt.Printf("| %-20s | %-36s |\n", "Ports", fmt.Sprintf("%d (%s)", len(ports), intsToCSV(ports)))
	fmt.Printf("| %-20s | %-36s |\n", "Open services", strconv.Itoa(hostPortCount))
	fmt.Printf("| %-20s | %-36s |\n", "Findings", strconv.Itoa(len(findings)))
	fmt.Printf("| %-20s | %-36s |\n", "Elapsed", elapsed.String())
	if outFile == "" {
		fmt.Printf("| %-20s | %-36s |\n", "Report", "stdout")
	} else {
		fmt.Printf("| %-20s | %-36s |\n", "Report", outFile)
	}
	fmt.Println("\x1b[1;34m+----------------------+--------------------------------------+\x1b[0m")

	if len(findings) > 0 {
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Target != findings[j].Target {
				return findings[i].Target < findings[j].Target
			}
			if findings[i].Port != findings[j].Port {
				return findings[i].Port < findings[j].Port
			}
			return findings[i].RuleID < findings[j].RuleID
		})

		fmt.Println("\x1b[35mFindings by target:port\x1b[0m")
		group := map[string]int{}
		for _, f := range findings {
			key := f.Target
			if f.Port > 0 {
				key = fmt.Sprintf("%s:%d", f.Target, f.Port)
			}
			group[key]++
		}
		keys := make([]string, 0, len(group))
		for k := range group {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Println("\x1b[1;34m+------------------------------+----------+\x1b[0m")
		fmt.Printf("\x1b[1;34m| %-28s | %-8s |\x1b[0m\n", "Target", "Findings")
		fmt.Println("\x1b[1;34m+------------------------------+----------+\x1b[0m")
		for _, k := range keys {
			fmt.Printf("| %-28s | %-8d |\n", k, group[k])
		}
		fmt.Println("\x1b[1;34m+------------------------------+----------+\x1b[0m")

		fmt.Println()
		fmt.Println("\x1b[35mFindings detail\x1b[0m")
		fmt.Println("\x1b[1;34m+-----+------------------------------+--------------------------------------+--------------------------------------+\x1b[0m")
		fmt.Printf("\x1b[1;34m| %-3s | %-28s | %-36s | %-36s |\x1b[0m\n", "#", "Target", "Rule", "AccessURL")
		fmt.Println("\x1b[1;34m+-----+------------------------------+--------------------------------------+--------------------------------------+\x1b[0m")
		for i, f := range findings {
			target := f.Target
			if f.Port > 0 {
				target = fmt.Sprintf("%s:%d", f.Target, f.Port)
			}
			rule := clip(f.RuleID, 36)
			access := clip(f.AccessURL, 36)
			fmt.Printf("| %-3d | %-28s | %-36s | %-36s |\n", i+1, clip(target, 28), rule, access)
		}
		fmt.Println("\x1b[1;34m+-----+------------------------------+--------------------------------------+--------------------------------------+\x1b[0m")
	}

	fmt.Println()
}

func printBanner() {
	const version = "v1.0.0"
	fmt.Println("\x1b[1;96m")
	fmt.Println(`   ██████╗██╗      █████╗ ██╗    ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ `)
	fmt.Println(`  ██╔════╝██║     ██╔══██╗██║    ██║██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗`)
	fmt.Println(`  ██║     ██║     ███████║██║ █╗ ██║███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝`)
	fmt.Println(`  ██║     ██║     ██╔══██║██║███╗██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗`)
	fmt.Println(`  ╚██████╗███████╗██║  ██║╚███╔███╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║`)
	fmt.Println(`   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝`)
	fmt.Println("\x1b[0m")
	fmt.Printf("\x1b[1m%-20s\x1b[0m %s\n", "author", "SherlockRen")
	fmt.Printf("\x1b[1m%-20s\x1b[0m %s\n", "version", version)
	fmt.Println()
}

func clip(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) <= n {
		return v
	}
	if n <= 3 {
		return v[:n]
	}
	return v[:n-3] + "..."
}

func normalizeFindings(findings []models.Finding) []models.Finding {
	if len(findings) == 0 {
		return findings
	}

	out := make([]models.Finding, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		key := fmt.Sprintf("%s|%d|%s|%s", f.Target, f.Port, f.RuleID, f.EvidencePattern)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func intsToCSV(v []int) string {
	if len(v) == 0 {
		return ""
	}
	parts := make([]string, 0, len(v))
	for _, n := range v {
		parts = append(parts, fmt.Sprintf("%d", n))
	}
	return strings.Join(parts, ",")
}
