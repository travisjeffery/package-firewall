package proxy

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/travisjeffery/package-firewall/internal/artifactcache"
	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/coordination"
)

type fillCall struct {
	done chan struct{}
}

type fillGroup struct {
	mu    sync.Mutex
	calls map[string]*fillCall
}

func (g *fillGroup) begin(key string) (*fillCall, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.calls == nil {
		g.calls = make(map[string]*fillCall)
	}
	if call, ok := g.calls[key]; ok {
		return call, false
	}
	call := &fillCall{done: make(chan struct{})}
	g.calls[key] = call
	return call, true
}

func (g *fillGroup) finish(key string, call *fillCall) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.calls[key] != call {
		return
	}
	delete(g.calls, key)
	close(call.done)
}

func (p *Proxy) serveCacheMiss(w http.ResponseWriter, r *http.Request, route config.RouteConfig, target, key string) (Result, error) {
	for {
		call, leader := p.fills.begin(key)
		if leader {
			return p.serveLocalFillLeader(w, r, route, target, key, call)
		}
		p.recordFillWaiter(route.Name, "process")
		select {
		case <-r.Context().Done():
			return Result{}, r.Context().Err()
		case <-call.done:
		}
		cached, err := p.loadCached(r, key)
		if err == nil {
			defer cached.Close()
			p.cache.Metrics.Hit(route.Name)
			return serveCached(w, cached, p.now())
		}
		if !errors.Is(err, artifactcache.ErrNotFound) {
			p.cache.Metrics.ReadError(route.Name)
			p.logger.Warn("artifact_cache_read_after_fill_failed", "route", route.Name, "error", err)
		}
	}
}

func (p *Proxy) serveLocalFillLeader(w http.ResponseWriter, r *http.Request, route config.RouteConfig, target, key string, call *fillCall) (Result, error) {
	if p.coordination.Coordinator == nil {
		p.recordFillLeader(route.Name)
		return p.serveUpstream(w, r, route, target, key, func() { p.fills.finish(key, call) })
	}
	recordedWaiter := false
	for {
		lease, acquired, err := p.coordination.Coordinator.TryAcquire(r.Context(), "artifact:"+key, p.coordination.LeaseDuration)
		if err != nil {
			p.fills.finish(key, call)
			return Result{}, err
		}
		if acquired {
			p.recordFillLeader(route.Name)
			fillContext, cancelFill := context.WithCancel(r.Context())
			stopLease := p.keepLease(lease, route.Name, key, cancelFill)
			return p.serveUpstream(w, r.Clone(fillContext), route, target, key, func() {
				stopLease()
				cancelFill()
				p.fills.finish(key, call)
			})
		}
		if !recordedWaiter {
			p.recordFillWaiter(route.Name, "cluster")
			recordedWaiter = true
		}
		select {
		case <-r.Context().Done():
			p.fills.finish(key, call)
			return Result{}, r.Context().Err()
		case <-time.After(p.coordination.PollInterval):
		}
		cached, cacheErr := p.loadCached(r, key)
		if cacheErr == nil {
			p.fills.finish(key, call)
			defer cached.Close()
			p.cache.Metrics.Hit(route.Name)
			return serveCached(w, cached, p.now())
		}
		if !errors.Is(cacheErr, artifactcache.ErrNotFound) {
			p.cache.Metrics.ReadError(route.Name)
			p.logger.Warn("artifact_cache_cluster_wait_read_failed", "route", route.Name, "error", cacheErr)
		}
	}
}

func (p *Proxy) keepLease(lease coordination.Lease, route, key string, cancelFill context.CancelFunc) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(p.coordination.LeaseDuration / 3)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(ctx, p.coordination.PollInterval)
				err := lease.Renew(renewCtx, p.coordination.LeaseDuration)
				renewCancel()
				if err != nil {
					p.logger.Warn("artifact_cache_fill_lease_renew_failed", "route", route, "cache_key", key, "error", err)
					cancelFill()
					return
				}
			}
		}
	}()
	return sync.OnceFunc(func() {
		cancel()
		<-done
		releaseTimeout := p.coordination.PollInterval
		if releaseTimeout > 5*time.Second {
			releaseTimeout = 5 * time.Second
		}
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer releaseCancel()
		if err := lease.Release(releaseCtx); err != nil && !errors.Is(err, coordination.ErrLeaseLost) {
			p.logger.Warn("artifact_cache_fill_lease_release_failed", "route", route, "cache_key", key, "error", err)
		}
	})
}

type fillMetrics interface {
	CacheFillLeader(string)
	CacheFillWaiter(string, string)
}

func (p *Proxy) recordFillLeader(route string) {
	if metrics, ok := p.cache.Metrics.(fillMetrics); ok {
		metrics.CacheFillLeader(route)
	}
}

func (p *Proxy) recordFillWaiter(route, scope string) {
	if metrics, ok := p.cache.Metrics.(fillMetrics); ok {
		metrics.CacheFillWaiter(route, scope)
	}
}
