// Command lynn-ui is a lossless subscription converter.
//
// It reads a proxy subscription (raw base64 links, one per line) and emits
// complete Clash (Mihomo) YAML, fixing the two conversion bugs found in
// the tools around it:
//
//   - 3x-ui's panel Clash generator drops obfs / obfs-password for
//     hysteria2 nodes that arrive as external links, and never emits sni
//     or skip-cert-verify for any hysteria2 node.
//   - sublink drops the VLESS+REALITY public-key (and
//     support-x25519mlkem768 / xhttp-opts).
//
// The raw subscription links are complete; lynn-ui parses them into one
// unified model and emits every field, treating local-inbound nodes and
// external-link nodes identically.
//
// Usage:
//
//	lynn-ui convert <url-or-file|-> [--out file]
//	lynn-ui serve [--addr :8080]
//	lynn-ui version
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/wonyeelynn/lynn-ui/converter"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "convert":
		cmdConvert(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("lynn-ui %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `lynn-ui - lossless subscription converter (fixes 3x-ui / sublink conversion bugs)

Usage:
  lynn-ui convert <url-or-file|-> [--out file] [--hy2-sni-host=true] [--hy2-skip-verify=true]
      Convert a subscription (URL, local file, or stdin "-") to Clash YAML on stdout.
  lynn-ui serve [--addr :8080] [--hy2-sni-host=true] [--hy2-skip-verify=true]
      HTTP server: GET /clash?url=<subscription-url>, POST /clash (body = links), GET /health
  lynn-ui version
`)
}

func optionsFromFlags(fs *flag.FlagSet) converter.Options {
	opts := converter.DefaultOptions()
	fs.BoolVar(&opts.HY2SNIHost, "hy2-sni-host", true,
		"when a hysteria2 link has no sni, use the server hostname as sni")
	fs.BoolVar(&opts.HY2SkipVerify, "hy2-skip-verify", true,
		"when a hysteria2 link has no insecure flag, emit skip-cert-verify: true")
	return opts
}

func cmdConvert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	opts := optionsFromFlags(fs)
	outPath := fs.String("out", "", "write Clash YAML to this file instead of stdout")
	fs.Usage = func() { usage() }
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "convert needs a subscription URL, file, or - (stdin)")
		os.Exit(2)
	}
	src := fs.Arg(0)
	input, err := readInput(src)
	if err != nil {
		fatal(err)
	}
	// Warn about skipped lines without failing the conversion.
	proxies, warnings, err := converter.ParseSubscriptionText(input, opts)
	if err != nil {
		fatal(err)
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	out, err := converter.BuildClash(proxies)
	if err != nil {
		fatal(err)
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			fatal(err)
		}
	} else {
		os.Stdout.Write(out)
	}
}

// readInput reads a subscription from a URL, a file, or stdin ("-").
func readInput(src string) (string, error) {
	if src == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return converter.FetchSubscription(src)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("read %q: %w", src, err)
	}
	return string(b), nil
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	opts := optionsFromFlags(fs)
	addr := fs.String("addr", ":8080", "listen address")
	fs.Usage = func() { usage() }
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`+"\n")
	})
	mux.HandleFunc("/clash", func(w http.ResponseWriter, r *http.Request) {
		var input string
		var err error
		switch r.Method {
		case http.MethodGet:
			u := r.URL.Query().Get("url")
			if u == "" {
				http.Error(w, "missing ?url=<subscription-url>", http.StatusBadRequest)
				return
			}
			input, err = converter.FetchSubscription(u)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		case http.MethodPost:
			b, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			input = string(b)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		proxies, warnings, err := converter.ParseSubscriptionText(input, opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		for _, warn := range warnings {
			fmt.Fprintln(os.Stderr, "warning:", warn)
		}
		out, err := converter.BuildClash(proxies)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Write(out)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "lynn-ui %s - lossless subscription converter\n\nGET  /clash?url=<subscription-url>  -> Clash YAML\nPOST /clash  (body = subscription links) -> Clash YAML\nGET  /health\n", version)
	})

	fmt.Fprintf(os.Stderr, "lynn-ui %s listening on %s\n", version, *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "lynn-ui:", err)
	os.Exit(1)
}
