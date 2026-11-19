package agent

// App console (dashboard "Console"): an interactive shell in an app container, relayed by the engine.
// The exec runs through the Docker Engine API on the local unix socket with Tty: true, so dockerd allocates the PTY
// (no pty dependency). Messages: engine -> console_open{id,container,cmd,cols,rows} | console_in{id,d(base64)} |
// console_resize{id,cols,rows} | console_close{id}; agent -> console_ready{id} | console_out{id,d(base64)} |
// console_exit{id,reason}. Keystrokes and output are never logged.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/protocol"
)

var containerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

type consoleSess struct {
	conn   net.Conn
	execID string
	once   sync.Once
}

var (
	consolesMu sync.Mutex
	consoles   = map[string]*consoleSess{}
)

func dockerSocketPath() string {
	if h := os.Getenv("DOCKER_HOST"); strings.HasPrefix(h, "unix://") {
		return strings.TrimPrefix(h, "unix://")
	}
	return "/var/run/docker.sock"
}

var dockerHTTP = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", dockerSocketPath())
	}},
}

func dockerAPI(method, path string, body any) (int, map[string]any, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://docker"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := dockerHTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out, nil
}

func (a *Agent) onConsole(m protocol.Message) {
	switch m.T {
	case "console_open":
		go a.consoleOpen(m)
	case "console_in":
		if s := getConsole(m.ID); s != nil {
			if b, err := base64.StdEncoding.DecodeString(m.D); err == nil {
				_, _ = s.conn.Write(b)
			}
		}
	case "console_resize":
		if s := getConsole(m.ID); s != nil && m.Cols > 0 && m.Rows > 0 && m.Cols <= 500 && m.Rows <= 300 {
			go func() {
				_, _, _ = dockerAPI("POST", fmt.Sprintf("/exec/%s/resize?h=%d&w=%d", s.execID, m.Rows, m.Cols), nil)
			}()
		}
	case "console_close":
		if s := getConsole(m.ID); s != nil {
			s.close()
		}
	}
}

func getConsole(id string) *consoleSess {
	consolesMu.Lock()
	defer consolesMu.Unlock()
	return consoles[id]
}

func (s *consoleSess) close() { s.once.Do(func() { _ = s.conn.Close() }) }

func (a *Agent) consoleOpen(m protocol.Message) {
	exit := func(reason string) { a.send(map[string]any{"t": "console_exit", "id": m.ID, "reason": reason}) }
	if !containerName.MatchString(m.Container) || len(m.Cmd) == 0 {
		exit("error")
		return
	}
	c := url.PathEscape(m.Container)
	st, info, err := dockerAPI("GET", "/containers/"+c+"/json", nil)
	running := false
	if state, ok := info["State"].(map[string]any); ok {
		running, _ = state["Running"].(bool)
	}
	if err != nil || st != 200 || !running {
		exit("not_running")
		return
	}
	cmd, env, helper := m.Cmd, []string{"TERM=xterm-256color"}, false
	if m.HelperTar != "" {
		if helperDirRe.MatchString(m.HelperDir) && len(m.FallbackCmd) > 0 && injectHelper(c, m.HelperTar) {
			helper = true
			env = append(env, helperEnv(m.Env)...)
		} else if len(m.FallbackCmd) > 0 {
			cmd = m.FallbackCmd
		}
	}
	st, ex, err := dockerAPI("POST", "/containers/"+c+"/exec", map[string]any{
		"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": true,
		"Env": env, "Cmd": cmd,
	})
	execID, _ := ex["Id"].(string)
	if err != nil || st != 201 || execID == "" {
		exit("error")
		return
	}
	conn, br, err := startExec(execID)
	if err != nil {
		exit("error")
		return
	}
	s := &consoleSess{conn: conn, execID: execID}
	consolesMu.Lock()
	consoles[m.ID] = s
	consolesMu.Unlock()
	if m.Cols > 0 && m.Rows > 0 {
		_, _, _ = dockerAPI("POST", fmt.Sprintf("/exec/%s/resize?h=%d&w=%d", execID, m.Rows, m.Cols), nil)
	}
	a.send(map[string]any{"t": "console_ready", "id": m.ID, "helper": helper})
	buf := make([]byte, 16*1024)
	for {
		n, rerr := br.Read(buf)
		if n > 0 {
			a.send(map[string]any{"t": "console_out", "id": m.ID, "d": base64.StdEncoding.EncodeToString(buf[:n])})
		}
		if rerr != nil {
			break
		}
	}
	s.close()
	consolesMu.Lock()
	delete(consoles, m.ID)
	consolesMu.Unlock()
	if helper {
		cleanupHelper(c, m.HelperDir)
	}
	exit("exited")
}

// startExec starts an exec with an upgraded (hijacked) connection: raw TTY bytes both ways.
func startExec(execID string) (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("unix", dockerSocketPath(), 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	body := `{"Detach":false,"Tty":true}`
	req := fmt.Sprintf("POST /exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n%s", execID, len(body), body)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	if res.StatusCode != http.StatusSwitchingProtocols && res.StatusCode != http.StatusOK {
		conn.Close()
		return nil, nil, fmt.Errorf("exec start: %d", res.StatusCode)
	}
	return conn, br, nil
}

// --- f2c console helper -------------------------------------------------------------------------------------

var helperDirRe = regexp.MustCompile(`^/tmp/\.f2c/con_[a-f0-9]{16}$`)
var helperEnvRe = regexp.MustCompile(`^F2C_[A-Z_]{1,32}=[^\x00\n]{0,256}$`)

// helperEnv keeps only F2C_* entries (the engine sends app name, runtime, health path and the session nonce).
func helperEnv(in []string) []string {
	out := []string{}
	for _, e := range in {
		if helperEnvRe.MatchString(e) && len(out) < 8 {
			out = append(out, e)
		}
	}
	return out
}

// injectHelper PUTs the engine's tar into the container's /tmp; false when /tmp is missing or read-only.
func injectHelper(container, b64 string) bool {
	tarb, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(tarb) > 256*1024 {
		return false
	}
	req, err := http.NewRequest("PUT", "http://docker/containers/"+container+"/archive?path=/tmp", bytes.NewReader(tarb))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-tar")
	res, err := dockerHTTP.Do(req)
	if err != nil {
		return false
	}
	res.Body.Close()
	return res.StatusCode == 200
}

// cleanupHelper removes the session's helper dir (exec as root, that exact validated path only).
func cleanupHelper(container, dir string) {
	if !helperDirRe.MatchString(dir) {
		return
	}
	st, ex, err := dockerAPI("POST", "/containers/"+container+"/exec", map[string]any{
		"User": "0", "Cmd": []string{"/bin/sh", "-c", "p=; [ -f " + dir + ".pid ] && read -r p < " + dir + ".pid; case \"$p\" in ''|*[!0-9]*) ;; *) kill -HUP \"$p\" 2>/dev/null;; esac; rm -rf " + dir + " " + dir + ".pid; rmdir /tmp/.f2c 2>/dev/null; true"},
	})
	if id, _ := ex["Id"].(string); err == nil && st == 201 && id != "" {
		_, _, _ = dockerAPI("POST", "/exec/"+id+"/start", map[string]any{"Detach": true, "Tty": false})
	}
}
