package monitor

import (
	"os/exec"
	"regexp"
	"strings"
)

type FirewallRule struct {
	Index    string
	To       string
	Action   string
	From     string
	Comment  string
	Protocol string
}

type FirewallInfo struct {
	Status string
	Rules  []FirewallRule
}

// GetFirewall returns status of ufw
func (m *Monitor) GetFirewall() *FirewallInfo {
	info := &FirewallInfo{
		Status: "inactive",
		Rules:  []FirewallRule{},
	}

	// Check if ufw is installed
	_, err := exec.LookPath("ufw")
	if err != nil {
		// Try common paths
		commonPaths := []string{"/usr/sbin/ufw", "/sbin/ufw"}
		found := false
		for _, p := range commonPaths {
			// Just try to run it with version check to see if it exists/runs
			if err := exec.Command(p, "--version").Run(); err == nil {
				found = true
				break
			}
		}
		if !found {
			info.Status = "not_installed"
			return info
		}
	}

	// Run ufw status numbered
	// We need sudo for ufw usually, but agent runs as root hopefully?
	// If not root, this might fail with "ERROR: You need to be root..."
	cmd := exec.Command("ufw", "status", "numbered")
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	if err != nil {
		// If permission denied or other error
		if strings.Contains(outStr, "You need to be root") {
			info.Status = "permission_denied"
		} else {
			info.Status = "error"
		}
		return info
	}

	if strings.Contains(outStr, "Status: active") {
		info.Status = "active"
	}

	if info.Status == "active" {
		lines := strings.Split(outStr, "\n")
		// Regex to parse: [ 1] 22/tcp ALLOW IN Anywhere
		re := regexp.MustCompile(`\[\s*(\d+)]\s+([\w/:.-]+(?:\s+\(v6\))?)\s+((?:ALLOW|DENY|REJECT|LIMIT)\s+(?:IN|OUT))\s+(.*)`)

		for _, line := range lines {
			line = strings.TrimSpace(line)
			matches := re.FindStringSubmatch(line)
			if len(matches) == 5 {
				toParts := strings.Split(matches[2], "/")
				protocol := ""
				if len(toParts) > 1 {
					protocol = toParts[1]
				}

				info.Rules = append(info.Rules, FirewallRule{
					Index:    matches[1],
					To:       matches[2],
					Action:   matches[3],
					From:     matches[4],
					Protocol: protocol,
				})
			}
		}
	}

	return info
}
