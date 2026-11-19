package docker

// 24 h registry read credentials pushed by the engine over the live wss connection
// ("registry_login", never queued). They are written to <state-dir>/docker/config.json (0600, atomic)
// and used only for `docker pull` via DOCKER_CONFIG. Never logged.

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

// RegistryConfigDir is set at startup (run); empty = pulls use the default docker config.
var RegistryConfigDir string

// Registry handles the registry_login frame: it only needs a way to send the reply.
type Registry struct {
	send func(any) bool
}

func parseRegistryConfig(raw json.RawMessage) ([]byte, error) {
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if len(raw) == 0 || len(raw) > 16<<10 || json.Unmarshal(raw, &cfg) != nil || len(cfg.Auths) == 0 || len(cfg.Auths) > 4 {
		return nil, protocol.BadRequest(errors.New("invalid registry config"))
	}
	for host, a := range cfg.Auths {
		if host == "" || len(host) > 253 || a.Auth == "" {
			return nil, protocol.BadRequest(errors.New("invalid registry config"))
		}
	}
	return json.Marshal(cfg)
}

func writeRegistryConfig(dir string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, "config.json"))
}

func (a *Registry) Login(m protocol.Message) {
	reply := map[string]any{"t": "registry_login", "id": m.ID, "ok": false}
	data, err := parseRegistryConfig(m.Config)
	if err == nil && RegistryConfigDir == "" {
		err = errors.New("no registry config dir")
	}
	if err == nil {
		err = writeRegistryConfig(RegistryConfigDir, data)
	}
	if err != nil {
		reply["error"] = err.Error()
		reply["code"] = protocol.V1Code(err) // sent only at protocol >= 1 (Agent.send drops it below)
	} else {
		log.Printf("registry read credentials updated")
		reply["ok"] = true
	}
	a.send(reply)
}

// pullEnv: DOCKER_CONFIG for pulls once credentials were received.
func pullEnv() []string {
	if RegistryConfigDir == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(RegistryConfigDir, "config.json")); err != nil {
		return nil
	}
	return append(os.Environ(), "DOCKER_CONFIG="+RegistryConfigDir)
}

// New builds the registry_login handler from a frame sender.
func New(send func(any) bool) *Registry {
	return &Registry{send: send}
}
