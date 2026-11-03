package intel

import (
	"fmt"
	"slices"
	"strings"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

func Decide(result Result, defaultAction policy.Action, blockThreshold float64) policy.Decision {
	if len(result.Findings) == 0 {
		return policy.Decision{Action: policy.ActionAllow, Reason: "no vulnerability findings"}
	}
	// Malicious-package records carry no CVSS score, so neither the threshold
	// nor the default action may decide them.
	if decision, ok := MalwareDecision(result, blockThreshold); ok {
		return decision
	}
	var blocking *Finding
	for i, finding := range result.Findings {
		if blockThreshold > 0 && finding.Severity >= blockThreshold && (blocking == nil || finding.Severity > blocking.Severity) {
			blocking = &result.Findings[i]
		}
	}
	if blocking != nil {
		return policy.Decision{
			Action:   policy.ActionBlock,
			Reason:   fmt.Sprintf("vulnerability %s severity %.1f exceeds threshold %.1f", blocking.ID, blocking.Severity, blockThreshold),
			Kind:     findingKind(*blocking),
			Advisory: advisory(*blocking, blockThreshold),
		}
	}
	ids := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		ids = append(ids, finding.ID)
	}
	if defaultAction == "" {
		defaultAction = policy.ActionWarn
	}
	worst := result.Findings[0]
	for _, finding := range result.Findings[1:] {
		if finding.Severity > worst.Severity {
			worst = finding
		}
	}
	return policy.Decision{
		Action:   defaultAction,
		Reason:   "vulnerability findings: " + strings.Join(ids, ","),
		Kind:     findingKind(worst),
		Advisory: advisory(worst, blockThreshold),
	}
}

// MalwareDecision returns the block for the first malicious finding, if any.
func MalwareDecision(result Result, blockThreshold float64) (policy.Decision, bool) {
	for _, finding := range result.Findings {
		if malicious(finding) {
			reason := "malicious package " + finding.ID
			if mal := malAlias(finding); mal != "" && mal != finding.ID {
				reason += " (" + mal + ")"
			}
			return policy.Decision{
				Action:   policy.ActionBlock,
				Reason:   reason,
				Kind:     policy.KindMalware,
				Advisory: advisory(finding, blockThreshold),
			}, true
		}
	}
	return policy.Decision{}, false
}

// OSV publishes the OpenSSF malicious-packages feed under the MAL- prefix. A
// GitHub malware advisory may alias that record, or carry no MAL- record and
// no severity at all, only CWE-506 (embedded malicious code), as coa@2.0.3's
// GHSA-73qr-pfmq-6rp8 does.
func malicious(finding Finding) bool {
	return malAlias(finding) != "" || slices.Contains(finding.CWEs, "CWE-506")
}

func malAlias(finding Finding) string {
	if strings.HasPrefix(finding.ID, "MAL-") {
		return finding.ID
	}
	for _, alias := range finding.Aliases {
		if strings.HasPrefix(alias, "MAL-") {
			return alias
		}
	}
	return ""
}

func findingKind(finding Finding) policy.BlockKind {
	if malicious(finding) {
		return policy.KindMalware
	}
	return policy.KindVulnerability
}

func advisory(finding Finding, threshold float64) *policy.Advisory {
	return &policy.Advisory{
		ID:        finding.ID,
		Aliases:   finding.Aliases,
		Summary:   finding.Summary,
		Severity:  finding.Severity,
		Threshold: threshold,
		Affected:  finding.Affected,
		Fixed:     finding.Fixed,
		URL:       "https://osv.dev/vulnerability/" + finding.ID,
	}
}
