package audit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

type Logger struct {
	logger *slog.Logger
}

type Event struct {
	Time           time.Time `json:"time"`
	RequestID      string    `json:"request_id"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Route          string    `json:"route"`
	Ecosystem      string    `json:"ecosystem"`
	PURL           string    `json:"purl,omitempty"`
	Action         string    `json:"action"`
	Reason         string    `json:"reason"`
	MatchedRule    string    `json:"matched_rule,omitempty"`
	UpstreamStatus int       `json:"upstream_status,omitempty"`
	Error          string    `json:"error,omitempty"`
}

func New() *Logger {
	return &Logger{logger: slog.New(slog.NewJSONHandler(os.Stdout, nil))}
}

func (l *Logger) Log(event Event) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	raw, err := json.Marshal(event)
	if err != nil {
		l.logger.Error("audit_event_encode_failed", "error", err)
		return
	}
	l.logger.Info("package_firewall_decision", "event", json.RawMessage(raw))
}

func FromDecision(r *http.Request, route string, pkg policy.Package, requestID string, decision policy.Decision) Event {
	return Event{
		Time:        time.Now().UTC(),
		RequestID:   requestID,
		Method:      r.Method,
		Path:        r.URL.Path,
		Route:       route,
		Ecosystem:   pkg.Ecosystem,
		PURL:        pkg.PURL,
		Action:      string(decision.Action),
		Reason:      decision.Reason,
		MatchedRule: decision.MatchedRule,
	}
}
