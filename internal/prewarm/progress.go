package prewarm

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type progressEvent struct {
	Time         time.Time `json:"time"`
	Event        string    `json:"event"`
	Pass         int       `json:"pass"`
	Artifact     string    `json:"artifact,omitempty"`
	Route        string    `json:"route,omitempty"`
	Attempt      int       `json:"attempt,omitempty"`
	Completed    int64     `json:"completed,omitempty"`
	Total        int       `json:"total"`
	ElapsedMS    int64     `json:"elapsed_ms"`
	PacingMS     int64     `json:"pacing_ms,omitempty"`
	HeadersMS    int64     `json:"headers_ms,omitempty"`
	BodyMS       int64     `json:"body_ms,omitempty"`
	Bytes        int64     `json:"bytes,omitempty"`
	HTTPStatus   int       `json:"http_status,omitempty"`
	CacheStatus  string    `json:"cache_status,omitempty"`
	RequestID    string    `json:"request_id,omitempty"`
	RetryDelayMS int64     `json:"retry_delay_ms,omitempty"`
	RetryAfter   bool      `json:"retry_after,omitempty"`
	Outcome      string    `json:"outcome,omitempty"`
}

type progressLogger struct {
	mu      sync.Mutex
	encoder *json.Encoder
	err     error
}

func newProgressLogger(output io.Writer) *progressLogger {
	if output == nil {
		return nil
	}
	return &progressLogger{encoder: json.NewEncoder(output)}
}

func (cfg RunConfig) emit(event progressEvent) {
	if cfg.progress == nil {
		return
	}
	cfg.progress.mu.Lock()
	defer cfg.progress.mu.Unlock()
	if cfg.progress.err != nil {
		return
	}
	event.Time = time.Now().UTC()
	event.Pass, event.Total, event.Attempt = cfg.pass, cfg.total, cfg.attempt
	cfg.progress.err = cfg.progress.encoder.Encode(event)
}
