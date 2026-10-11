package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Data is the persisted state saved to and loaded from disk.
type Data struct {
	Monitors []string  `json:"monitors"`
	Webhooks []RawHook `json:"webhooks"`
}

// RawHook mirrors webhook.Webhook without importing that package (avoids cycles).
type RawHook struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

// Store provides atomic read/write of persisted data.
type Store struct {
	mu   sync.Mutex
	path string
}

// DefaultPath returns where the agent keeps its state when XYTHERION_DATA_FILE
// is unset: /var/lib/xytherion/data.json for a root service on Linux, otherwise
// ~/.xytherion/data.json. It never depends on the working directory, which is
// "/" under systemd and launchd.
func DefaultPath() string {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return "/var/lib/xytherion/data.json"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".xytherion", "data.json")
	}
	return ".xytherion.json"
}

// New creates a Store backed by path. The file is created on first Save.
func New(path string) *Store {
	return &Store{path: path}
}

// Path returns the file path this store uses.
func (s *Store) Path() string { return s.path }

// Load reads persisted data from disk. Returns empty Data if the file does not exist.
func (s *Store) Load() (Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var d Data
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		// Earlier versions wrote .xytherion.json in the working directory.
		if legacy, lerr := os.Open(".xytherion.json"); lerr == nil {
			defer legacy.Close()
			return d, json.NewDecoder(legacy).Decode(&d)
		}
		return d, nil
	}
	if err != nil {
		return d, err
	}
	defer f.Close()
	return d, json.NewDecoder(f).Decode(&d)
}

// Save writes data to disk atomically via a temp file + rename.
func (s *Store) Save(d Data) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Webhook URLs embed secrets (Slack/Discord tokens): keep the file private.
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.path)
}
