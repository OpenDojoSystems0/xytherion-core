// signtool manages the ed25519 key that signs Xytherion releases.
//
//	go run ./scripts/signtool keygen -out ~/.config/xytherion-signing/update.key
//	go run ./scripts/signtool sign checksums.txt > checksums.txt.sig
//	go run ./scripts/signtool sign-manifest -version v0.3.1 -url https://… -sha <sha256>
//	go run ./scripts/signtool verify checksums.txt checksums.txt.sig
//
// The private key is read from -key FILE or the XYTHERION_SIGNING_KEY
// environment variable (base64), which is how CI provides it. Never commit it.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xytherion/core/internal/selfupdate"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "sign":
		sign(os.Args[2:])
	case "sign-manifest":
		signManifest(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: signtool keygen -out FILE | sign [-key FILE] FILE | sign-manifest [-key FILE] -version V -url U -sha S | verify FILE SIGFILE")
	os.Exit(2)
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "signtool: "+format+"\n", a...)
	os.Exit(1)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "where to write the private key (created with mode 0600)")
	fs.Parse(args)
	if *out == "" {
		fail("-out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		fail("%s already exists — refusing to overwrite a signing key", *out)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail("generate: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		fail("%v", err)
	}
	if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		fail("%v", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
}

func loadKey(path string) ed25519.PrivateKey {
	raw := os.Getenv("XYTHERION_SIGNING_KEY")
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			fail("%v", err)
		}
		raw = string(b)
	}
	if strings.TrimSpace(raw) == "" {
		fail("no signing key: pass -key FILE or set XYTHERION_SIGNING_KEY")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		fail("invalid signing key")
	}
	return ed25519.PrivateKey(key)
}

func sign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file (default: $XYTHERION_SIGNING_KEY)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fail("sign takes exactly one file")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fail("%v", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(ed25519.Sign(loadKey(*keyFile), data)))
}

func signManifest(args []string) {
	fs := flag.NewFlagSet("sign-manifest", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file (default: $XYTHERION_SIGNING_KEY)")
	version := fs.String("version", "", "release version, e.g. v0.3.1")
	url := fs.String("url", "", "HTTPS URL of the binary")
	sha := fs.String("sha", "", "SHA-256 of the binary")
	fs.Parse(args)
	if *version == "" || *url == "" || len(*sha) != 64 {
		fail("-version, -url and a 64-char -sha are required")
	}
	msg := selfupdate.ManifestMessage(*version, *url, *sha)
	fmt.Println(base64.StdEncoding.EncodeToString(ed25519.Sign(loadKey(*keyFile), msg)))
}

// verify checks a signature against the public key embedded in the agent, so a
// release can never ship with a key the agents would reject.
func verify(args []string) {
	if len(args) != 2 {
		fail("verify takes a file and its signature file")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fail("%v", err)
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		fail("%v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		fail("signature is not valid base64")
	}
	pub, err := base64.StdEncoding.DecodeString(selfupdate.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fail("embedded public key is invalid")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		fail("signature does NOT match the public key embedded in the agent — wrong signing key?")
	}
	fmt.Println("signature OK")
}
