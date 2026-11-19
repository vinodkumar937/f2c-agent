// Command f2c-agent runs on an F2C app server. It dials the engine over WSS (/agent), sends a heartbeat every
// 15s, and executes engine commands (pull, run, stop, rm, logs, stats, exec, caddy_apply, cert_install, http_probe) against
// the local Docker and Caddy. It only touches containers it created (label f2c.agent=1).
//
//	f2c-agent join --engine https://engine.example --token f2cj_...   # one-time: exchange for a server token
//	f2c-agent reattach                                                # after engine lost this server: submit identity+inventory as orphan
//	f2c-agent run                                                     # connect and serve commands
//	f2c-agent version
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/vinodkumar937/f2c-agent/internal/agent"
	"github.com/vinodkumar937/f2c-agent/internal/config"
	"github.com/vinodkumar937/f2c-agent/internal/docker"
	"github.com/vinodkumar937/f2c-agent/internal/version"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "join":
		fs := flag.NewFlagSet("join", flag.ExitOnError)
		engine := fs.String("engine", "", "engine base URL (https://...)")
		token := fs.String("token", "", "one-time join token (f2cj_...)")
		stateDir := fs.String("state-dir", defaultStateDir(), "agent state directory")
		provider := fs.String("provider", "", "provider label (e.g. digitalocean, hostinger)")
		publicIP := fs.String("public-ip", "", "public IP to report (default: cloud metadata on DigitalOcean, else the public address the engine sees)")
		insecure := fs.Bool("insecure", false, "deprecated: plain http is only allowed to a loopback engine")
		_ = fs.Parse(os.Args[2:])
		if *engine == "" || *token == "" {
			log.Fatal("join: --engine and --token are required")
		}
		if err := config.Join(*engine, *token, *stateDir, *provider, *publicIP, *insecure); err != nil {
			log.Fatalf("join: %v", err)
		}
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		stateDir := fs.String("state-dir", defaultStateDir(), "agent state directory")
		caddyAdmin := fs.String("caddy-admin", "http://127.0.0.1:2019", "local Caddy admin API")
		certDir := fs.String("cert-dir", "", "certificate directory (default <state-dir>/certs)")
		insecure := fs.Bool("insecure", false, "deprecated: ws:// is only allowed to a loopback engine")
		caddyCerts := fs.String("caddy-certs", "/var/lib/caddy/.local/share/caddy/certificates", "Caddy certificate storage to watch for issued certs (step 4)")
		accessListen := fs.String("access-listen", "127.0.0.1:9181", "loopback address for Caddy's JSON access log (feature C)")
		askListen := fs.String("ask-listen", "127.0.0.1:9180", "loopback address for Caddy's on-demand TLS ask (/tls/ask)")
		_ = fs.Parse(os.Args[2:])
		cfg, err := config.Load(*stateDir)
		if err != nil {
			log.Fatalf("run: %v (run `f2c-agent join` first)", err)
		}
		if *certDir == "" {
			*certDir = *stateDir + "/certs"
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		docker.RegistryConfigDir = filepath.Join(*stateDir, "docker")
		a := agent.New(cfg, *stateDir, *caddyAdmin, *certDir, *insecure)
		a.Run(ctx, *askListen, *accessListen, *caddyCerts)
	case "reattach":
		fs := flag.NewFlagSet("reattach", flag.ExitOnError)
		engine := fs.String("engine", "", "engine base URL (default: from agent.json)")
		stateDir := fs.String("state-dir", defaultStateDir(), "agent state directory")
		caddyAdmin := fs.String("caddy-admin", "http://127.0.0.1:2019", "local Caddy admin API")
		publicIP := fs.String("public-ip", "", "public IP to report")
		insecure := fs.Bool("insecure", false, "deprecated: plain http is only allowed to a loopback engine")
		_ = fs.Parse(os.Args[2:])
		if err := agent.Reattach(*engine, *stateDir, *caddyAdmin, *publicIP, *insecure); err != nil {
			log.Fatalf("reattach: %v", err)
		}
	case "version":
		fmt.Println(version.Version)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: f2c-agent join --engine URL --token TOKEN | reattach [--engine URL] | run | version")
	os.Exit(2)
}

func defaultStateDir() string {
	if d := os.Getenv("F2C_AGENT_STATE_DIR"); d != "" {
		return d
	}
	return "/var/lib/f2c-agent"
}
