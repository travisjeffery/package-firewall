package intel

import (
	"fmt"
	"strings"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

func Decide(result Result, defaultAction policy.Action, blockThreshold float64) policy.Decision {
	if len(result.Findings) == 0 {
		return policy.Decision{Action: policy.ActionAllow, Reason: "no vulnerability findings"}
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

// OSV publishes the OpenSSF malicious-packages feed under the MAL- prefix.
func findingKind(finding Finding) policy.BlockKind {
	if strings.HasPrefix(finding.ID, "MAL-") {
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
