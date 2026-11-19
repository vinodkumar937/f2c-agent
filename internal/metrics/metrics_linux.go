//go:build linux

package metrics

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type metrics struct {
	CPUPct      float64
	MemTotalMb  float64
	MemUsedMb   float64
	DiskTotalGb float64
	DiskUsedGb  float64
}

var (
	cpuMu             sync.Mutex
	lastIdle, lastAll uint64
)

func cpuPct() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	var all, idle uint64
	for i, s := range f[1:] {
		v, _ := strconv.ParseUint(s, 10, 64)
		all += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	first := lastAll == 0
	dAll, dIdle := all-lastAll, idle-lastIdle
	lastAll, lastIdle = all, idle
	if first || dAll == 0 {
		return 0
	}
	return round2(100 * float64(dAll-dIdle) / float64(dAll))
}

func Collect(path string) metrics {
	m := metrics{CPUPct: cpuPct()}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail float64
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseFloat(f[1], 64)
			switch f[0] {
			case "MemTotal:":
				total = v
			case "MemAvailable:":
				avail = v
			}
		}
		m.MemTotalMb, m.MemUsedMb = round2(total/1024), round2((total-avail)/1024)
	}
	m.DiskTotalGb, m.DiskUsedGb = disk("/")
	return m
}

func disk(p string) (float64, float64) {
	var s syscall.Statfs_t
	if syscall.Statfs(p, &s) != nil {
		return 0, 0
	}
	total := float64(s.Blocks) * float64(s.Bsize)
	free := float64(s.Bavail) * float64(s.Bsize)
	return round2(total / 1e9), round2((total - free) / 1e9)
}

func round2(v float64) float64 { return float64(int64(v*100)) / 100 }
