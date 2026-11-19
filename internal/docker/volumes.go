package docker

// Read-only Docker volume inventory for the `volumes_list` command.
// Reuses collectVolumeInventory (reattach.go).

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

func CollectVolumeInventory(ctx context.Context) []string {
	out, err := exec.CommandContext(ctx, "docker", "volume", "ls", "-q", "--filter", "name=^f2c-").Output()
	if err != nil {
		return []string{}
	}
	list := []string{}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "f2c-") {
			list = append(list, l)
		}
	}
	return list
}

func VolumesList(ctx context.Context, _ map[string]any) (any, error) {
	names := CollectVolumeInventory(ctx)
	volApp := map[string]string{}
	if list, err := ManagedContainers(ctx); err == nil {
		for _, c := range list {
			mounts, err := CLI(ctx, "inspect", "-f",
				`{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}{{end}}`,
				c.Name)
			if err != nil {
				continue
			}
			appLabel, _ := CLI(ctx, "inspect", "-f", `{{index .Config.Labels "f2c.app"}}`, c.Name)
			appLabel = strings.TrimSpace(appLabel)
			if appLabel == "" {
				continue
			}
			for _, line := range strings.Split(mounts, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "f2c-") {
					volApp[line] = appLabel
				}
			}
		}
	}

	volumes := make([]map[string]any, 0, len(names))
	for _, name := range names {
		entry := map[string]any{"name": name}
		mp, err := CLI(ctx, "volume", "inspect", "-f", "{{.Mountpoint}}", name)
		mp = strings.TrimSpace(mp)
		if err == nil && mp != "" {
			entry["mountpoint"] = mp
			if sizeOut, err := exec.CommandContext(ctx, "du", "-sb", mp).Output(); err == nil {
				fields := strings.Fields(string(sizeOut))
				if len(fields) >= 1 {
					if n, e := strconv.ParseInt(fields[0], 10, 64); e == nil && n >= 0 {
						entry["sizeBytes"] = n
					}
				}
			}
		}
		if app := volApp[name]; app != "" {
			entry["appName"] = app
			entry["appId"] = app
		}
		volumes = append(volumes, entry)
	}
	return map[string]any{"volumes": volumes}, nil
}
