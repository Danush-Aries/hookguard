// hookguard is a static security scanner for Claude Code hook configurations.
//
// Usage:
//
//	hookguard scan [path]       # scan a directory (default: cwd)
//	hookguard scan --json       # emit JSON findings for CI
//	hookguard list-rules        # print the rule catalog
//	hookguard version           # print version
//
// Exit codes:
//
//	0  no findings, or only info/low
//	1  medium findings present
//	2  high or critical findings present (fail CI)
//	3  usage or IO error
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Danush-Aries/hookguard/internal/rules"
	"github.com/Danush-Aries/hookguard/internal/scanner"
)

// Version is set by goreleaser via -ldflags at build time.
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(3)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "list-rules":
		os.Exit(cmdListRules(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("hookguard", Version)
		os.Exit(0)
	case "help", "-h", "--help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "hookguard: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(3)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `hookguard - static security scanner for Claude Code hooks

Usage:
  hookguard scan [path] [--json] [--fail-on SEVERITY]
  hookguard list-rules [--json]
  hookguard version

Flags:
  --json            emit JSON output
  --fail-on LEVEL   minimum severity that returns non-zero exit
                    (info|low|medium|high|critical, default: high)

Exit codes:
  0 clean or below --fail-on threshold
  1 medium
  2 high or critical
  3 usage/IO error
`)
}

// ---------------- scan ----------------

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON findings")
	failOn := fs.String("fail-on", "high", "minimum severity that returns non-zero exit")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hookguard: bad path:", err)
		return 3
	}
	res, err := scanner.Scan(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hookguard: scan error:", err)
		return 3
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintln(os.Stderr, "hookguard: encode:", err)
			return 3
		}
	} else {
		printHuman(res)
	}
	return exitFor(res, *failOn)
}

func printHuman(res *scanner.Result) {
	fmt.Printf("hookguard scan: %s\n", res.Root)
	if res.SettingsAt == "" {
		fmt.Println("  no .claude/settings.json found - nothing to scan")
		return
	}
	fmt.Printf("  settings: %s\n", res.SettingsAt)
	fmt.Printf("  hooks:    %d\n", len(res.Hooks))
	fmt.Printf("  findings: %d (crit=%d high=%d med=%d low=%d info=%d)\n\n",
		res.Summary.Total, res.Summary.Critical, res.Summary.High,
		res.Summary.Medium, res.Summary.Low, res.Summary.Info)
	if len(res.Findings) == 0 {
		fmt.Println("clean: no rules triggered.")
		return
	}
	for _, f := range res.Findings {
		loc := f.ScriptPath
		if loc == "" {
			loc = "(inline)"
		}
		fmt.Printf("[%s] %s  %s\n", strings.ToUpper(string(f.Severity)), f.RuleID, f.Title)
		fmt.Printf("    event:  %s\n", f.Event)
		fmt.Printf("    where:  %s:%d\n", loc, f.Line)
		if f.Snippet != "" {
			fmt.Printf("    line:   %s\n", f.Snippet)
		}
		fmt.Printf("    why:    %s\n\n", f.Message)
	}
}

func exitFor(res *scanner.Result, failOn string) int {
	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	threshold, ok := order[strings.ToLower(failOn)]
	if !ok {
		threshold = order["high"]
	}
	worst := -1
	if res.Summary.Info > 0 {
		worst = 0
	}
	if res.Summary.Low > 0 {
		worst = 1
	}
	if res.Summary.Medium > 0 {
		worst = 2
	}
	if res.Summary.High > 0 {
		worst = 3
	}
	if res.Summary.Critical > 0 {
		worst = 4
	}
	if worst < threshold {
		return 0
	}
	if worst >= 3 {
		return 2
	}
	if worst == 2 {
		return 1
	}
	return 0
}

// ---------------- list-rules ----------------

func cmdListRules(args []string) int {
	fs := flag.NewFlagSet("list-rules", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	rs := rules.All()
	if *jsonOut {
		type row struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Title       string `json:"title"`
			Description string `json:"description"`
		}
		var rows []row
		for _, r := range rs {
			rows = append(rows, row{r.ID, string(r.Severity), r.Title, r.Description})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return 0
	}
	fmt.Println("hookguard rules:")
	for _, r := range rs {
		fmt.Printf("  %s  [%s]  %s\n", r.ID, r.Severity, r.Title)
		fmt.Printf("        %s\n", r.Description)
	}
	return 0
}
