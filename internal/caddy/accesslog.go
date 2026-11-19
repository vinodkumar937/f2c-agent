package caddy

// Per-app request metrics from this server's Caddy. The engine-pushed Caddy config sends app-route
// access entries (JSON, client IPs/headers/token already removed by Caddy's filter encoder) to a TCP "net" writer on
// 127.0.0.1:9181. The agent aggregates per host per minute and send finished minutes in the heartbeat ("access"); the engine
// maps hosts to apps (extra public-service domains are first reported under their app's primary host, accessmap.go). Nothing is written to disk.

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"math"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const accessMaxSamples = 2000

type accessBucket struct {
	Requests, S2xx, S3xx, S4xx, S5xx int
	Bytes                            int64
	samples                          []float64
}

var (
	accessMu      sync.Mutex
	accessBuckets = map[string]map[string]*accessBucket{} // minute RFC3339 -> host -> bucket
)

type accessEntry struct {
	Ts       float64 `json:"ts"`
	Status   int     `json:"status"`
	Size     int64   `json:"size"`
	Duration float64 `json:"duration"`
	Request  struct {
		Host string `json:"host"`
	} `json:"request"`
}

func recordAccess(line []byte, now time.Time) {
	var e accessEntry
	if json.Unmarshal(line, &e) != nil || e.Request.Host == "" {
		return
	}
	t := now
	if e.Ts > 0 {
		t = time.Unix(0, int64(e.Ts*1e9))
	}
	minute := t.UTC().Truncate(time.Minute).Format(time.RFC3339)
	host := strings.ToLower(e.Request.Host)
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	host = accessHostFor(host) // an extra public service's domain counts for its parent app
	accessMu.Lock()
	defer accessMu.Unlock()
	m := accessBuckets[minute]
	if m == nil {
		if len(accessBuckets) > 10 { // engine unreachable for a long time: drop the oldest
			var oldest string
			for k := range accessBuckets {
				if oldest == "" || k < oldest {
					oldest = k
				}
			}
			delete(accessBuckets, oldest)
		}
		m = map[string]*accessBucket{}
		accessBuckets[minute] = m
	}
	b := m[host]
	if b == nil {
		if len(m) > 2000 {
			return
		}
		b = &accessBucket{}
		m[host] = b
	}
	b.Requests++
	switch {
	case e.Status >= 500:
		b.S5xx++
	case e.Status >= 400:
		b.S4xx++
	case e.Status >= 300:
		b.S3xx++
	case e.Status >= 200:
		b.S2xx++
	}
	if e.Size > 0 {
		b.Bytes += e.Size
	}
	ms := e.Duration * 1000
	if ms >= 0 && !math.IsNaN(ms) {
		if len(b.samples) < accessMaxSamples {
			b.samples = append(b.samples, ms)
		} else {
			b.samples[rand.Intn(accessMaxSamples)] = ms
		}
	}
}

func percentile(s []float64, p float64) any {
	if len(s) == 0 {
		return nil
	}
	i := int(math.Floor(p*float64(len(s)-1) + 0.5))
	return math.Round(s[i]*10) / 10
}

// TakeAccessMinutes returns and removes every finished minute (before now's minute).
func TakeAccessMinutes(now time.Time) []map[string]any {
	cur := now.UTC().Truncate(time.Minute).Format(time.RFC3339)
	accessMu.Lock()
	defer accessMu.Unlock()
	var out []map[string]any
	for minute, m := range accessBuckets {
		if minute >= cur {
			continue
		}
		for host, b := range m {
			sort.Float64s(b.samples)
			out = append(out, map[string]any{
				"host": host, "minute": minute, "requests": b.Requests, "s2xx": b.S2xx, "s3xx": b.S3xx, "s4xx": b.S4xx, "s5xx": b.S5xx,
				"bytes": b.Bytes, "p50Ms": percentile(b.samples, 0.5), "p95Ms": percentile(b.samples, 0.95),
			})
		}
		delete(accessBuckets, minute)
	}
	return out
}

func ServeAccessLog(ctx context.Context, addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("access log: listen %s: %v", addr, err)
		return
	}
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Second)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				recordAccess(sc.Bytes(), time.Now())
			}
		}(c)
	}
}
