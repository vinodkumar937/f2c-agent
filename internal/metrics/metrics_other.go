//go:build !linux

package metrics

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Development fallback (macOS): memory from sysctl/vm_stat, CPU from ps, disk via statfs.
type metrics struct {
	CPUPct      float64
	MemTotalMb  float64
	MemUsedMb   float64
	DiskTotalGb float64
	DiskUsedGb  float64
}

func Collect(path string) metrics {
	var m metrics
	if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
		v, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
		m.MemTotalMb = round2(v / 1048576)
	}
	if out, err := exec.Command("vm_stat").Output(); err == nil {
		page, used := 16384.0, 0.0
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, "page size of") {
				for _, f := range strings.Fields(l) {
					if v, err := strconv.ParseFloat(f, 64); err == nil {
						page = v
					}
				}
			}
			for _, k := range []string{"Pages active:", "Pages wired down:", "Pages occupied by compressor:"} {
				if strings.HasPrefix(l, k) {
					v, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(l, k)), "."), 64)
					used += v
				}
			}
		}
		m.MemUsedMb = round2(used * page / 1048576)
	}
	if out, err := exec.Command("ps", "-A", "-o", "%cpu=").Output(); err == nil {
		sum := 0.0
		for _, f := range strings.Fields(string(out)) {
			v, _ := strconv.ParseFloat(f, 64)
			sum += v
		}
		m.CPUPct = round2(sum / float64(runtime.NumCPU()))
	}
	var s syscall.Statfs_t
	if syscall.Statfs("/", &s) == nil {
		total := float64(s.Blocks) * float64(s.Bsize)
		free := float64(s.Bavail) * float64(s.Bsize)
		m.DiskTotalGb, m.DiskUsedGb = round2(total/1e9), round2((total-free)/1e9)
	}
	return m
}

func round2(v float64) float64 { return float64(int64(v*100)) / 100 }
