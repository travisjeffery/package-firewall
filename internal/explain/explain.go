package explain

import (
	"fmt"
	"strings"
	"time"

	"github.com/travisjeffery/tidewaiter/internal/policy"
)

type Explanation struct {
	Blocked       bool             `json:"blocked"`
	Action        string           `json:"action"`
	Kind          string           `json:"kind,omitempty"`
	Ecosystem     string           `json:"ecosystem,omitempty"`
	Package       string           `json:"package,omitempty"`
	PURL          string           `json:"purl,omitempty"`
	Reason        string           `json:"reason"`
	Rule          string           `json:"rule,omitempty"`
	Advisory      *policy.Advisory `json:"advisory,omitempty"`
	AllowedAfter  *time.Time       `json:"allowed_after,omitempty"`
	NextStep      string           `json:"next_step,omitempty"`
	ExceptionsURL string           `json:"exceptions_url,omitempty"`
	RequestID     string           `json:"request_id,omitempty"`
	Message       string           `json:"message"`
}

func New(pkg policy.Package, decision policy.Decision, requestID, exceptionsURL string) Explanation {
	e := Explanation{
		Blocked:       decision.Action == policy.ActionBlock,
		Action:        string(decision.Action),
		Kind:          string(decision.Kind),
		Ecosystem:     pkg.Ecosystem,
		Package:       packageLabel(pkg),
		PURL:          pkg.PURL,
		Reason:        decision.Reason,
		Rule:          decision.MatchedRule,
		Advisory:      decision.Advisory,
		ExceptionsURL: exceptionsURL,
		RequestID:     requestID,
	}
	if !decision.AllowedAfter.IsZero() {
		allowedAfter := decision.AllowedAfter.UTC()
		e.AllowedAfter = &allowedAfter
	}
	e.NextStep = nextStep(e, decision)
	e.Message = message(e)
	return e
}

// HeaderValue returns the message as a single printable-ASCII line, since
// header values cannot carry newlines and many clients mangle non-ASCII.
func HeaderValue(value string, limit int) string {
	var b strings.Builder
	for _, r := range strings.Join(strings.Fields(value), " ") {
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > limit {
		out = out[:limit-3] + "..."
	}
	return out
}

func message(e Explanation) string {
	subject := e.Package
	if subject == "" {
		subject = "this request"
	}
	var b strings.Builder
	if e.Blocked {
		b.WriteString("Blocked by Tidewaiter: ")
	} else if e.Action == string(policy.ActionAllow) {
		fmt.Fprintf(&b, "Tidewaiter allows %s: %s.", subject, e.Reason)
		return b.String()
	} else {
		fmt.Fprintf(&b, "Tidewaiter allows %s (action %s): ", subject, e.Action)
	}
	b.WriteString(finding(e, subject))
	if e.NextStep != "" {
		b.WriteString(" ")
		b.WriteString(e.NextStep)
	}
	if e.Advisory != nil && e.Advisory.URL != "" {
		fmt.Fprintf(&b, " Details: %s.", e.Advisory.URL)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " Request ID: %s.", e.RequestID)
	}
	if e.Blocked && e.ExceptionsURL != "" {
		fmt.Fprintf(&b, " Exceptions: %s", e.ExceptionsURL)
	}
	return strings.TrimSpace(b.String())
}

func finding(e Explanation, subject string) string {
	a := e.Advisory
	kind := policy.BlockKind(e.Kind)
	if a == nil && (kind == policy.KindMalware || kind == policy.KindVulnerability) {
		kind = ""
	}
	switch kind {
	case policy.KindMalware:
		return fmt.Sprintf("%s is a known malicious package (%s)%s.", subject, advisoryIDs(a), summary(a))
	case policy.KindVulnerability:
		var text string
		switch {
		case a.Threshold > 0 && a.Severity >= a.Threshold:
			text = fmt.Sprintf("%s has %s, severity %.1f >= threshold %.1f%s.", subject, advisoryIDs(a), a.Severity, a.Threshold, summary(a))
		case e.Blocked:
			text = fmt.Sprintf("%s has %s, severity %.1f%s; the severity threshold does not block it, but the default vulnerability action does.", subject, advisoryIDs(a), a.Severity, summary(a))
		default:
			text = fmt.Sprintf("%s has %s, severity %.1f below threshold %.1f%s.", subject, advisoryIDs(a), a.Severity, a.Threshold, summary(a))
		}
		if len(a.Affected) > 0 {
			text += " Affected: " + strings.Join(a.Affected, "; ") + "."
		}
		return text
	case policy.KindPolicyRule:
		return fmt.Sprintf("%s matches %s rule %s.", subject, ruleName(e.Action), e.Rule)
	case policy.KindCooldown:
		if e.AllowedAfter != nil {
			return fmt.Sprintf("%s was published too recently for the release cooldown; it is allowed after %s.", subject, e.AllowedAfter.Format(time.RFC3339))
		}
		return fmt.Sprintf("%s was published too recently for the release cooldown.", subject)
	case policy.KindUnknownPackage:
		return "the package and version could not be identified from the request path."
	case policy.KindIntelError:
		return fmt.Sprintf("the vulnerability lookup for %s failed.", subject)
	default:
		return fmt.Sprintf("%s: %s.", subject, e.Reason)
	}
}

func nextStep(e Explanation, decision policy.Decision) string {
	if !e.Blocked {
		return ""
	}
	switch decision.Kind {
	case policy.KindMalware:
		return "Remove the dependency and treat any machine that installed it as compromised."
	case policy.KindVulnerability:
		if decision.Advisory != nil && len(decision.Advisory.Fixed) > 0 {
			return fmt.Sprintf("Fixed in %s; upgrade to a fixed version (update the lockfile, or override the transitive dependency).", strings.Join(decision.Advisory.Fixed, ", "))
		}
		return "No fixed version is published; remove or replace the dependency, or request an exception."
	case policy.KindPolicyRule:
		return "Use a different package or version, or request an exception."
	case policy.KindCooldown:
		return "Pin an earlier version until then."
	case policy.KindUnknownPackage:
		return "Check the request URL; request an exception if it is a legitimate artifact."
	case policy.KindIntelError:
		return "Retry the install; the lookup fails closed while the vulnerability service is unavailable."
	default:
		return ""
	}
}

func advisoryIDs(a *policy.Advisory) string {
	if len(a.Aliases) == 0 {
		return a.ID
	}
	return fmt.Sprintf("%s (%s)", a.ID, strings.Join(a.Aliases, ", "))
}

func summary(a *policy.Advisory) string {
	text := strings.Join(strings.Fields(a.Summary), " ")
	if text == "" {
		return ""
	}
	return ": " + strings.TrimSuffix(text, ".")
}

func ruleName(action string) string {
	if action == string(policy.ActionBlock) {
		return "deny"
	}
	return action
}

func packageLabel(pkg policy.Package) string {
	if pkg.Name == "" {
		return ""
	}
	if pkg.Version == "" {
		return pkg.Name
	}
	return pkg.Name + "@" + pkg.Version
}
