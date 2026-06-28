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
	for _, finding := range result.Findings {
		if finding.Severity >= blockThreshold && blockThreshold > 0 {
			return policy.Decision{
				Action: policy.ActionBlock,
				Reason: fmt.Sprintf("vulnerability %s severity %.1f exceeds threshold %.1f", finding.ID, finding.Severity, blockThreshold),
			}
		}
	}
	ids := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		ids = append(ids, finding.ID)
	}
	if defaultAction == "" {
		defaultAction = policy.ActionWarn
	}
	return policy.Decision{Action: defaultAction, Reason: "vulnerability findings: " + strings.Join(ids, ",")}
}
