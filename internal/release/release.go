// Package release looks up when a package version was published, for the
// release cooldown. An artifact URL does not carry its publish time, so it comes
// from the registry metadata the route proxies.
package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/travisjeffery/tidewaiter/internal/cache"
	"github.com/travisjeffery/tidewaiter/internal/registry"
)

const (
	// Full npm packuments run to tens of MiB; they are streamed, not buffered.
	maxNPMPackumentBytes = 256 << 20
	maxPyPIIndexBytes    = 64 << 20
	maxGoInfoBytes       = 64 << 10
	cacheEntries         = 16384
	cacheTTL             = 24 * time.Hour
)

type Resolver struct {
	client *http.Client
	cache  *cache.Cache[time.Time]
}

func NewResolver(client *http.Client) *Resolver {
	return &Resolver{client: client, cache: cache.NewWithMaxEntries[time.Time](cacheEntries)}
}

// PublishedAt returns when the requested artifact was published: the version's
// time for npm, Go and Maven, and the file's upload time for PyPI, since a file
// can be added to an old release. It returns the zero time for an ecosystem with
// no publish time to look up, which the cooldown does not apply to.
func (r *Resolver) PublishedAt(ctx context.Context, route registry.Route, info registry.RequestInfo) (time.Time, error) {
	pkg := info.Package
	if pkg.Name == "" || pkg.Version == "" {
		return time.Time{}, errors.New("package version is not identified")
	}
	key := route.Name + "|" + pkg.PURL + "|" + info.UpstreamPath
	if published, ok := r.cache.Get(key); ok {
		return published, nil
	}
	var (
		published time.Time
		err       error
	)
	switch route.Ecosystem {
	case "npm":
		published, err = r.npm(ctx, route, pkg.Name, pkg.Version)
	case "pypi":
		published, err = r.pypi(ctx, route, pkg.Name, path.Base(info.UpstreamPath))
	case "go":
		published, err = r.golang(ctx, route, info.UpstreamPath)
	case "maven":
		published, err = r.maven(ctx, route, info.UpstreamPath)
	default:
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	if published.IsZero() {
		return time.Time{}, fmt.Errorf("%s has no publish time", pkg.PURL)
	}
	r.cache.Set(key, published, cacheTTL)
	return published, nil
}

func (r *Resolver) npm(ctx context.Context, route registry.Route, name, version string) (time.Time, error) {
	resp, err := r.get(ctx, route, http.MethodGet, route.UpstreamURL, url.PathEscape(name), "application/json")
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	times, err := npmTimes(io.LimitReader(resp.Body, maxNPMPackumentBytes))
	if err != nil {
		return time.Time{}, fmt.Errorf("npm packument %s: %w", name, err)
	}
	raw, ok := times[version]
	if !ok {
		return time.Time{}, fmt.Errorf("npm packument %s has no time for %s", name, version)
	}
	return time.Parse(time.RFC3339, raw)
}

// npmTimes reads only the top-level "time" object, skipping "versions" token by
// token so a large packument is never held in memory.
func npmTimes(body io.Reader) (map[string]string, error) {
	dec := json.NewDecoder(body)
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if tok == "time" {
			var times map[string]string
			if err := dec.Decode(&times); err != nil {
				return nil, err
			}
			return times, nil
		}
		if err := skipValue(dec); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("no time field")
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != want {
		return fmt.Errorf("expected %q, got %v", want, tok)
	}
	return nil
}

func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return nil
		}
	}
}

// PEP 691 JSON index with PEP 700 upload times, served by any compliant index.
func (r *Resolver) pypi(ctx context.Context, route registry.Route, name, filename string) (time.Time, error) {
	resp, err := r.get(ctx, route, http.MethodGet, route.UpstreamURL, "simple/"+url.PathEscape(name)+"/", "application/vnd.pypi.simple.v1+json")
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	var index struct {
		Files []struct {
			Filename   string `json:"filename"`
			UploadTime string `json:"upload-time"`
		} `json:"files"`
	}
	if err := decodeLimited(resp.Body, maxPyPIIndexBytes, &index); err != nil {
		return time.Time{}, fmt.Errorf("pypi index %s: %w", name, err)
	}
	filename, _ = url.PathUnescape(filename)
	for _, file := range index.Files {
		if file.Filename == filename {
			if file.UploadTime == "" {
				return time.Time{}, fmt.Errorf("pypi index %s has no upload-time for %s", name, filename)
			}
			return time.Parse(time.RFC3339Nano, file.UploadTime)
		}
	}
	return time.Time{}, fmt.Errorf("pypi index %s does not list %s", name, filename)
}

func (r *Resolver) golang(ctx context.Context, route registry.Route, upstreamPath string) (time.Time, error) {
	ext := path.Ext(upstreamPath)
	if ext != ".info" && ext != ".mod" && ext != ".zip" {
		return time.Time{}, fmt.Errorf("go path %s is not a module version file", upstreamPath)
	}
	resp, err := r.get(ctx, route, http.MethodGet, route.UpstreamURL, strings.TrimSuffix(upstreamPath, ext)+".info", "application/json")
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	var info struct {
		Time time.Time `json:"Time"`
	}
	if err := decodeLimited(resp.Body, maxGoInfoBytes, &info); err != nil {
		return time.Time{}, fmt.Errorf("go info %s: %w", upstreamPath, err)
	}
	return info.Time, nil
}

// Maven repositories publish no per-version timestamp, but an artifact is
// immutable once deployed, so its Last-Modified is when it was published.
func (r *Resolver) maven(ctx context.Context, route registry.Route, upstreamPath string) (time.Time, error) {
	resp, err := r.get(ctx, route, http.MethodHead, route.UpstreamURL, upstreamPath, "*/*")
	if err != nil {
		return time.Time{}, err
	}
	resp.Body.Close()
	modified := resp.Header.Get("Last-Modified")
	if modified == "" {
		return time.Time{}, fmt.Errorf("maven artifact %s has no Last-Modified", upstreamPath)
	}
	return http.ParseTime(modified)
}

func (r *Resolver) get(ctx context.Context, route registry.Route, method, base, rel, accept string) (*http.Response, error) {
	target := strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(rel, "/")
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if route.UpstreamTokenEnv != "" {
		if token := os.Getenv(route.UpstreamTokenEnv); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s returned %d", method, target, resp.StatusCode)
	}
	return resp, nil
}

func decodeLimited(body io.Reader, maximum int64, v any) error {
	raw, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > maximum {
		return fmt.Errorf("response exceeds %d bytes", maximum)
	}
	return json.Unmarshal(raw, v)
}
