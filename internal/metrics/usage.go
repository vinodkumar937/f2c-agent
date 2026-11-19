package metrics

// Per-app usage (RAM/CPU/disk): sent batched in every 4th heartbeat (~60s).
// CPU/memory come from the container's cgroup when readable, else from ONE `docker stats --no-stream`
// call for all running managed containers. Disk (writable layer + the app's own named volumes) is
// measured at most every 30 min, cached, under a timeout; database volumes included (their data size).

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vinodkumar937/f2c-agent/internal/docker"
)

// UsageVersion is the capability flag the engine checks ("usageV" in the heartbeat). Bump on shape changes.
const UsageVersion = 1

const (
	usageEveryBeats = 4
	diskEvery       = 30 * time.Minute
	diskTimeout     = 2 * time.Minute
	statsTimeout    = 20 * time.Second
)

type appUsage struct {
	Name       string   `json:"name"`
	State      string   `json:"state"`
	CPUPct     *float64 `json:"cpuPct,omitempty"`
	CPULimit   *float64 `json:"cpuLimit,omitempty"`
	MemUsedMb  *float64 `json:"memUsedMb,omitempty"`
	MemLimitMb *float64 `json:"memLimitMb,omitempty"`
	DiskUsedMb *float64 `json:"diskUsedMb,omitempty"`
	// ImageSizeMb is the container image's size (cached per image id); diskUsedMb is only what the app wrote.
	ImageSizeMb    *float64 `json:"imageSizeMb,omitempty"`
	DiskMeasuredAt string   `json:"diskMeasuredAt,omitempty"`
	// DiskSkipped lists volumes whose measurement failed or timed out.
	DiskSkipped []string `json:"diskSkipped,omitempty"`
	Source      string   `json:"source,omitempty"` // "cgroup" | "docker_stats"
}

type cpuSample struct {
	usec uint64
	at   time.Time
}

type diskEntry struct {
	mb      float64
	imageMb *float64
	skipped []string
	at      time.Time
}

var (
	usageMu   sync.Mutex
	beatCount int
	lastCPU   = map[string]cpuSample{}
	diskCache = map[string]diskEntry{}
	// imageSizeCache: image id -> MB. Image contents never change for an id, so entries are kept for good.
	imageSizeCache = map[string]float64{}
	diskAt         time.Time
	diskBusy       bool
)

// UsageDue reports whether this heartbeat should carry per-app usage (every 4th beat, starting with the first).
func UsageDue() bool {
	usageMu.Lock()
	defer usageMu.Unlock()
	due := beatCount%usageEveryBeats == 0
	beatCount++
	return due
}

type runningContainer struct{ id, name, state string }

func listManaged(ctx context.Context) ([]runningContainer, error) {
	out, err := docker.CLI(ctx, "ps", "-a", "--no-trunc", "--filter", "label="+docker.ManagedLabel+"=1", "--format", "{{.ID}}\t{{.Names}}\t{{.State}}")
	if err != nil {
		return nil, err
	}
	list := []runningContainer{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 3 {
			list = append(list, runningContainer{f[0], f[1], f[2]})
		}
	}
	return list, nil
}

func AppUsage(ctx context.Context) []appUsage {
	ctx, cancel := context.WithTimeout(ctx, statsTimeout)
	defer cancel()
	list, err := listManaged(ctx)
	if err != nil {
		return nil
	}
	rows := make([]appUsage, 0, len(list))
	var fallback []int
	now := time.Now()
	for _, c := range list {
		r := appUsage{Name: c.name, State: c.state}
		if c.state == "running" {
			if ok := fillFromCgroup(&r, c.id, now); ok {
				r.Source = "cgroup"
			} else {
				fallback = append(fallback, len(rows))
			}
		}
		rows = append(rows, r)
	}
	if len(fallback) > 0 {
		names := make([]string, 0, len(fallback))
		for _, i := range fallback {
			names = append(names, rows[i].Name)
		}
		if out, err := docker.CLI(ctx, append([]string{"stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"}, names...)...); err == nil {
			for _, l := range strings.Split(out, "\n") {
				f := strings.Split(l, "\t")
				if len(f) != 3 {
					continue
				}
				for _, i := range fallback {
					if rows[i].Name == f[0] {
						applyDockerStats(&rows[i], f[1], f[2])
					}
				}
			}
		}
	}
	attachDisk(rows, list)
	return rows
}

// cgroupDir finds the container's cgroup v2 directory (systemd or cgroupfs driver); "" when not readable.
func cgroupDir(id string) string {
	for _, d := range []string{
		"/sys/fs/cgroup/system.slice/docker-" + id + ".scope",
		"/sys/fs/cgroup/docker/" + id,
	} {
		if _, err := os.Stat(filepath.Join(d, "cpu.stat")); err == nil {
			return d
		}
	}
	return ""
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func fillFromCgroup(r *appUsage, id string, now time.Time) bool {
	d := cgroupDir(id)
	if d == "" {
		return false
	}
	var usec uint64
	for _, l := range strings.Split(readTrim(filepath.Join(d, "cpu.stat")), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "usage_usec" {
			usec, _ = strconv.ParseUint(f[1], 10, 64)
		}
	}
	mem, err := strconv.ParseFloat(readTrim(filepath.Join(d, "memory.current")), 64)
	if err != nil {
		return false
	}
	// Match `docker stats`: exclude reclaimable page cache (inactive_file).
	for _, l := range strings.Split(readTrim(filepath.Join(d, "memory.stat")), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "inactive_file" {
			if v, e := strconv.ParseFloat(f[1], 64); e == nil && v < mem {
				mem -= v
			}
		}
	}
	r.MemUsedMb = ptr(round2(mem / 1048576))
	if v := readTrim(filepath.Join(d, "memory.max")); v != "" && v != "max" {
		if n, e := strconv.ParseFloat(v, 64); e == nil {
			r.MemLimitMb = ptr(round2(n / 1048576))
		}
	}
	if f := strings.Fields(readTrim(filepath.Join(d, "cpu.max"))); len(f) == 2 && f[0] != "max" {
		q, e1 := strconv.ParseFloat(f[0], 64)
		p, e2 := strconv.ParseFloat(f[1], 64)
		if e1 == nil && e2 == nil && p > 0 {
			r.CPULimit = ptr(round2(q / p))
		}
	}
	usageMu.Lock()
	prev, ok := lastCPU[id]
	lastCPU[id] = cpuSample{usec, now}
	usageMu.Unlock()
	if ok && usec >= prev.usec {
		if el := now.Sub(prev.at).Microseconds(); el > 0 {
			// CLI stats convention: 100% = one full core.
			r.CPUPct = ptr(round2(100 * float64(usec-prev.usec) / float64(el)))
		}
	}
	return true
}

var memUnitRe = regexp.MustCompile(`^([\d.]+)\s*([kKMGT]?i?B)$`)

// parseMem turns docker's "123.4MiB" / "1.5GiB" / "512kB" into MB.
func parseMem(s string) *float64 {
	m := memUnitRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return nil
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return nil
	}
	mult := map[string]float64{"B": 1.0 / 1048576, "KiB": 1.0 / 1024, "kB": 1.0 / 1024, "KB": 1.0 / 1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024, "TiB": 1048576, "TB": 1048576}
	k, ok := mult[m[2]]
	if !ok {
		return nil
	}
	return ptr(round2(v * k))
}

func applyDockerStats(r *appUsage, cpu, mem string) {
	if v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(cpu), "%"), 64); err == nil {
		r.CPUPct = ptr(round2(v))
	}
	if p := strings.SplitN(mem, "/", 2); len(p) == 2 {
		r.MemUsedMb = parseMem(p[0])
		r.MemLimitMb = parseMem(p[1])
	}
	r.Source = "docker_stats"
}

// attachDisk copies cached disk numbers onto rows and starts a background refresh when stale.
func attachDisk(rows []appUsage, list []runningContainer) {
	usageMu.Lock()
	stale := !diskBusy && time.Since(diskAt) >= diskEvery
	if stale {
		diskBusy = true
	}
	for i := range rows {
		if e, ok := diskCache[rows[i].Name]; ok {
			rows[i].DiskUsedMb = ptr(e.mb)
			rows[i].ImageSizeMb = e.imageMb
			rows[i].DiskMeasuredAt = e.at.UTC().Format(time.RFC3339)
			rows[i].DiskSkipped = e.skipped
		}
	}
	usageMu.Unlock()
	if stale {
		go refreshDisk(list)
	}
}

func refreshDisk(list []runningContainer) {
	defer func() {
		usageMu.Lock()
		diskBusy = false
		diskAt = time.Now()
		usageMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), diskTimeout)
	defer cancel()
	sizes := map[string]float64{}
	if out, err := docker.CLI(ctx, "ps", "-a", "--size", "--filter", "label="+docker.ManagedLabel+"=1", "--format", "{{.Names}}\t{{.Size}}"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			f := strings.SplitN(l, "\t", 2)
			if len(f) == 2 {
				// "12.3MB (virtual 200MB)": the first figure is the writable layer.
				if v := parseMem(strings.Fields(f[1] + " ")[0]); v != nil {
					sizes[f[0]] = *v
				}
			}
		}
	}
	for _, c := range list {
		if ctx.Err() != nil {
			return
		}
		e := diskEntry{mb: sizes[c.name], at: time.Now()}
		out, err := docker.CLI(ctx, "inspect", "-f", `{{.Image}}{{"\n"}}{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}|{{.Source}}{{"\n"}}{{end}}{{end}}`, c.id)
		if err == nil {
			lines := strings.Split(out, "\n")
			e.imageMb = imageSizeMb(ctx, strings.TrimSpace(lines[0]))
			for _, l := range lines[1:] {
				p := strings.SplitN(strings.TrimSpace(l), "|", 2)
				if len(p) != 2 || p[0] == "" {
					continue
				}
				// Database volumes are measured too (data size for the DB pages); a walk cut short by the
				// timeout is reported in diskSkipped instead of as a partial size.
				kb, ok := duKB(ctx, p[1])
				if !ok {
					e.skipped = append(e.skipped, p[0])
					continue
				}
				e.mb += kb / 1024
			}
		}
		e.mb = round2(e.mb)
		usageMu.Lock()
		diskCache[c.name] = e
		usageMu.Unlock()
	}
}

// imageSizeMb returns the image's size in MB, from the per-id cache or one `docker image inspect`.
func imageSizeMb(ctx context.Context, id string) *float64 {
	if id == "" {
		return nil
	}
	usageMu.Lock()
	v, ok := imageSizeCache[id]
	usageMu.Unlock()
	if ok {
		return ptr(v)
	}
	out, err := docker.CLI(ctx, "image", "inspect", "-f", "{{.Size}}", id)
	if err != nil {
		return nil
	}
	b, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
	if err != nil || b < 0 {
		return nil
	}
	v = round2(b / 1048576)
	usageMu.Lock()
	imageSizeCache[id] = v
	usageMu.Unlock()
	return ptr(v)
}

func duKB(ctx context.Context, path string) (float64, bool) {
	out, err := exec.CommandContext(ctx, "du", "-sk", path).Output()
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}

func ptr(v float64) *float64 { return &v }
