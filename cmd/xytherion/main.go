package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/xytherion/core/internal/selfupdate"
	"github.com/xytherion/core/internal/server"
)

// Version is injected at build time via -ldflags="-X main.Version=vX.Y.Z".
var Version = "dev"

func main() {
	port := flag.Int("port", 9001, "port to listen on")
	interval := flag.Duration("interval", time.Second, "collection interval")
	ring := flag.Int("ring", 3600, "ring buffer size (number of snapshots)")
	// The dashboard is served by the agent itself (same origin), so CORS only
	// matters for development servers of the dashboard UI.
	cors := flag.String("cors", "http://localhost:3092,http://localhost:3093", "extra allowed CORS origins, comma-separated ('*' allows all)")
	showVer := flag.Bool("version", false, "print the version and exit")
	update := flag.Bool("update", false, "install the latest signed release, then exit (restart the service afterwards)")
	flag.Parse()

	if *showVer {
		fmt.Printf("xytherion %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *update {
		os.Exit(runUpdate())
	}

	s := server.New(*port, *interval, *ring, *cors, Version)
	s.Run()
}

// runUpdate implements `xytherion --update` for manual or scripted upgrades.
func runUpdate() int {
	u := selfupdate.New(os.Getenv("XYTHERION_UPDATE_URL"), Version)
	rel, err := u.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "xytherion: %v\n", err)
		return 1
	}
	if rel == nil {
		fmt.Printf("xytherion %s est à jour.\n", Version)
		return 0
	}
	exe, err := selfupdate.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "xytherion: %v\n", err)
		return 1
	}
	fmt.Printf("Mise à jour %s → %s…\n", Version, rel.Version)
	if err := u.ApplyTo(rel, exe); err != nil {
		fmt.Fprintf(os.Stderr, "xytherion: %v\n", err)
		return 1
	}
	fmt.Printf("✓ xytherion %s installé (signature et SHA-256 vérifiés).\n", rel.Version)
	fmt.Println("Redémarrez l'agent : sudo systemctl restart xytherion (Linux) ou launchctl kickstart -k gui/$(id -u)/com.xytherion.agent (macOS).")
	return 0
}
