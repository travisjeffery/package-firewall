package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/explain"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

type fakePublishTimes struct {
	published time.Time
	err       error
	lookups   int
}

func (f *fakePublishTimes) PublishedAt(context.Context, registry.Route, registry.RequestInfo) (time.Time, error) {
	f.lookups++
	return f.published, f.err
}

func cooldownServer(t *testing.T, policyCfg policy.Config, failOpen bool, times *fakePublishTimes) (http.Handler, *bool) {
	t.Helper()
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	cfg := config.Default()
	cfg.Decision.FailOpenIntelErrors = failOpen
	cfg.Routes = []config.RouteConfig{{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: upstream.URL + "/"}}
	engine, err := policy.New(policyCfg)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, engine, intel.NoopProvider{})
	s.release = times
	return s.routesHandler(), &upstreamHit
}

var cooldown24h = policy.Config{Cooldown: policy.CooldownConfig{Enabled: true, MinAge: 24 * time.Hour}}

func TestCooldownBlocksAVersionPublishedTooRecently(t *testing.T) {
	published := time.Now().Add(-time.Hour)
	handler, upstreamHit := cooldownServer(t, cooldown24h, true, &fakePublishTimes{published: published})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
	if rec.Code != http.StatusForbidden || *upstreamHit {
		t.Fatalf("status = %d upstream hit = %v body = %s", rec.Code, *upstreamHit, rec.Body.String())
	}
	var body struct {
		Explanation explain.Explanation `json:"explanation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	e := body.Explanation
	if e.Kind != string(policy.KindCooldown) || e.AllowedAfter == nil || !e.AllowedAfter.Equal(published.Add(24*time.Hour)) {
		t.Fatalf("explanation = %+v", e)
	}
}

func TestCooldownServesAVersionOlderThanMinAge(t *testing.T) {
	handler, upstreamHit := cooldownServer(t, cooldown24h, true, &fakePublishTimes{published: time.Now().Add(-48 * time.Hour)})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
	if rec.Code != http.StatusOK || !*upstreamHit {
		t.Fatalf("status = %d upstream hit = %v", rec.Code, *upstreamHit)
	}
}

func TestCooldownLookupFailureFollowsFailOpenIntelErrors(t *testing.T) {
	for _, tt := range []struct {
		failOpen bool
		want     int
	}{{true, http.StatusOK}, {false, http.StatusForbidden}} {
		handler, _ := cooldownServer(t, cooldown24h, tt.failOpen, &fakePublishTimes{err: errors.New("registry down")})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
		if rec.Code != tt.want {
			t.Fatalf("fail open %v: status = %d body = %s", tt.failOpen, rec.Code, rec.Body.String())
		}
	}
}

func TestPublishTimeIsNotLookedUpWhenItCannotChangeTheDecision(t *testing.T) {
	for name, cfg := range map[string]policy.Config{
		"cooldown disabled":  {},
		"allow rule matched": {Allow: []string{"pkg:npm/left-pad@*"}, Cooldown: cooldown24h.Cooldown},
	} {
		t.Run(name, func(t *testing.T) {
			times := &fakePublishTimes{published: time.Now()}
			handler, _ := cooldownServer(t, cfg, true, times)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/npm/left-pad/-/left-pad-1.3.0.tgz", nil))
			if rec.Code != http.StatusOK || times.lookups != 0 {
				t.Fatalf("status = %d lookups = %d", rec.Code, times.lookups)
			}
		})
	}
}
