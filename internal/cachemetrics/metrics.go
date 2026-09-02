package cachemetrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type Metrics struct {
	mu                sync.RWMutex
	hits              map[string]uint64
	misses            map[string]uint64
	storeErrors       map[string]uint64
	readErrors        map[string]uint64
	bypasses          map[bypassKey]uint64
	fillLeaders       map[string]uint64
	fillWaiters       map[fillWaiterKey]uint64
	upstreamRequests  map[upstreamStatusKey]uint64
	upstreamInFlight  map[string]int64
	upstreamRetries   map[upstreamReasonKey]uint64
	upstreamThrottled map[upstreamReasonKey]uint64
}

type bypassKey struct {
	route  string
	reason string
}

type fillWaiterKey struct {
	route string
	scope string
}

type upstreamStatusKey struct {
	route  string
	status string
}

type upstreamReasonKey struct {
	route  string
	reason string
}

func New() *Metrics {
	return &Metrics{
		hits:              make(map[string]uint64),
		misses:            make(map[string]uint64),
		storeErrors:       make(map[string]uint64),
		readErrors:        make(map[string]uint64),
		bypasses:          make(map[bypassKey]uint64),
		fillLeaders:       make(map[string]uint64),
		fillWaiters:       make(map[fillWaiterKey]uint64),
		upstreamRequests:  make(map[upstreamStatusKey]uint64),
		upstreamInFlight:  make(map[string]int64),
		upstreamRetries:   make(map[upstreamReasonKey]uint64),
		upstreamThrottled: make(map[upstreamReasonKey]uint64),
	}
}

func (m *Metrics) Hit(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits[route]++
}

func (m *Metrics) Miss(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.misses[route]++
}

func (m *Metrics) StoreError(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeErrors[route]++
}

func (m *Metrics) ReadError(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readErrors[route]++
}

func (m *Metrics) Bypass(route, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bypasses[bypassKey{route: route, reason: reason}]++
}

func (m *Metrics) CacheFillLeader(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fillLeaders[route]++
}

func (m *Metrics) CacheFillWaiter(route, scope string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fillWaiters[fillWaiterKey{route: route, scope: scope}]++
}

func (m *Metrics) UpstreamRequest(route, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamRequests[upstreamStatusKey{route: route, status: status}]++
}

func (m *Metrics) UpstreamInFlight(route string, delta int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamInFlight[route] += int64(delta)
}

func (m *Metrics) UpstreamRetry(route, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamRetries[upstreamReasonKey{route: route, reason: reason}]++
}

func (m *Metrics) UpstreamThrottled(route, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamThrottled[upstreamReasonKey{route: route, reason: reason}]++
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = m.WriteTo(w)
	})
}

func (m *Metrics) WriteTo(writer io.Writer) (int64, error) {
	m.mu.RLock()
	hits := cloneMap(m.hits)
	misses := cloneMap(m.misses)
	storeErrors := cloneMap(m.storeErrors)
	readErrors := cloneMap(m.readErrors)
	fillLeaders := cloneMap(m.fillLeaders)
	upstreamInFlight := cloneInt64Map(m.upstreamInFlight)
	bypasses := make(map[bypassKey]uint64, len(m.bypasses))
	for key, value := range m.bypasses {
		bypasses[key] = value
	}
	fillWaiters := make(map[fillWaiterKey]uint64, len(m.fillWaiters))
	for key, value := range m.fillWaiters {
		fillWaiters[key] = value
	}
	upstreamRequests := cloneUpstreamStatuses(m.upstreamRequests)
	upstreamRetries := cloneUpstreamReasons(m.upstreamRetries)
	upstreamThrottled := cloneUpstreamReasons(m.upstreamThrottled)
	m.mu.RUnlock()

	counting := &countingWriter{writer: writer}
	writeCounter(counting, "package_firewall_cache_hits_total", "Artifact cache hits after a complete integrity-checked read.", hits)
	writeCounter(counting, "package_firewall_cache_misses_total", "Artifact cache misses, including cache read failures that fell back to upstream.", misses)
	writeCounter(counting, "package_firewall_cache_store_errors_total", "Artifact cache staging or backend store errors.", storeErrors)
	writeCounter(counting, "package_firewall_cache_read_errors_total", "Artifact cache lookup, staging, or integrity errors.", readErrors)
	writeCounter(counting, "package_firewall_cache_fill_leaders_total", "Artifact cache misses elected to download from an upstream registry.", fillLeaders)
	writeFillWaiters(counting, fillWaiters)
	writeUpstreamStatuses(counting, "package_firewall_upstream_requests_total", "Request attempts sent to upstream registries by response status.", upstreamRequests)
	writeGauge(counting, "package_firewall_upstream_in_flight", "Upstream response bodies currently in flight.", upstreamInFlight)
	writeUpstreamReasons(counting, "package_firewall_upstream_retries_total", "Upstream request retries by bounded reason.", upstreamRetries)
	writeUpstreamReasons(counting, "package_firewall_upstream_throttled_total", "Requests delayed or rejected by upstream protection.", upstreamThrottled)
	writeBypasses(counting, bypasses)
	return counting.written, counting.err
}

func writeGauge(writer io.Writer, name, help string, values map[string]int64) {
	_, _ = fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	routes := make([]string, 0, len(values))
	for route := range values {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	for _, route := range routes {
		_, _ = fmt.Fprintf(writer, "%s{route=\"%s\"} %d\n", name, escapeLabel(route), values[route])
	}
}

func writeUpstreamStatuses(writer io.Writer, name, help string, values map[upstreamStatusKey]uint64) {
	_, _ = fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([]upstreamStatusKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route == keys[j].route {
			return keys[i].status < keys[j].status
		}
		return keys[i].route < keys[j].route
	})
	for _, key := range keys {
		_, _ = fmt.Fprintf(writer, "%s{route=\"%s\",status=\"%s\"} %d\n", name, escapeLabel(key.route), escapeLabel(key.status), values[key])
	}
}

func writeUpstreamReasons(writer io.Writer, name, help string, values map[upstreamReasonKey]uint64) {
	_, _ = fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([]upstreamReasonKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route == keys[j].route {
			return keys[i].reason < keys[j].reason
		}
		return keys[i].route < keys[j].route
	})
	for _, key := range keys {
		_, _ = fmt.Fprintf(writer, "%s{route=\"%s\",reason=\"%s\"} %d\n", name, escapeLabel(key.route), escapeLabel(key.reason), values[key])
	}
}

func writeFillWaiters(writer io.Writer, values map[fillWaiterKey]uint64) {
	const name = "package_firewall_cache_fill_waiters_total"
	_, _ = fmt.Fprintf(writer, "# HELP %s Artifact cache misses coalesced behind another fill.\n# TYPE %s counter\n", name, name)
	keys := make([]fillWaiterKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route == keys[j].route {
			return keys[i].scope < keys[j].scope
		}
		return keys[i].route < keys[j].route
	})
	for _, key := range keys {
		_, _ = fmt.Fprintf(
			writer,
			"%s{route=\"%s\",scope=\"%s\"} %d\n",
			name,
			escapeLabel(key.route),
			escapeLabel(key.scope),
			values[key],
		)
	}
}

func writeCounter(writer io.Writer, name, help string, values map[string]uint64) {
	_, _ = fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	routes := make([]string, 0, len(values))
	for route := range values {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	for _, route := range routes {
		_, _ = fmt.Fprintf(writer, "%s{route=\"%s\"} %d\n", name, escapeLabel(route), values[route])
	}
}

func writeBypasses(writer io.Writer, values map[bypassKey]uint64) {
	const name = "package_firewall_cache_bypasses_total"
	_, _ = fmt.Fprintf(writer, "# HELP %s Artifact cache bypasses labeled by bounded reason.\n# TYPE %s counter\n", name, name)
	keys := make([]bypassKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route == keys[j].route {
			return keys[i].reason < keys[j].reason
		}
		return keys[i].route < keys[j].route
	})
	for _, key := range keys {
		_, _ = fmt.Fprintf(
			writer,
			"%s{route=\"%s\",reason=\"%s\"} %d\n",
			name,
			escapeLabel(key.route),
			escapeLabel(key.reason),
			values[key],
		)
	}
}

func cloneMap(source map[string]uint64) map[string]uint64 {
	clone := make(map[string]uint64, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func cloneInt64Map(source map[string]int64) map[string]int64 {
	clone := make(map[string]int64, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func cloneUpstreamStatuses(source map[upstreamStatusKey]uint64) map[upstreamStatusKey]uint64 {
	clone := make(map[upstreamStatusKey]uint64, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func cloneUpstreamReasons(source map[upstreamReasonKey]uint64) map[upstreamReasonKey]uint64 {
	clone := make(map[upstreamReasonKey]uint64, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

type countingWriter struct {
	writer  io.Writer
	written int64
	err     error
}

func (w *countingWriter) Write(body []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	written, err := w.writer.Write(body)
	w.written += int64(written)
	w.err = err
	return written, err
}
