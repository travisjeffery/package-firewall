package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"testing/iotest"

	"github.com/travisjeffery/tidewaiter/internal/config"
	"github.com/travisjeffery/tidewaiter/internal/registry"
)

// The whole-body rewrite this replaced is the oracle: streaming must produce the
// same bytes wherever the reads happen to split a URL.
func TestRewriteStreamMatchesWholeBodyRewriteAtEveryReadBoundary(t *testing.T) {
	rules := New("http://firewall.test").rewriteRules(config.RouteConfig{Ecosystem: "pypi", PathPrefix: "/pypi/"})
	for _, body := range []string{
		`https://files.pythonhosted.org/https://files.pythonhosted.org/a.whl http://files.pythonhosted.org/b.whl`,
		`<a href="http://files.pythonhosted.org/c.whl">https://files.pythonhosted.org/`,
		`ends on a partial match https://files.pythonhosted.or`,
		`no match at all`,
		``,
	} {
		want := []byte(body)
		for _, rule := range rules {
			want = bytes.ReplaceAll(want, rule.old, rule.new)
		}
		readers := map[string]io.Reader{
			"whole":         bytes.NewReader([]byte(body)),
			"one byte":      iotest.OneByteReader(bytes.NewReader([]byte(body))),
			"data with EOF": iotest.DataErrReader(bytes.NewReader([]byte(body))),
		}
		for split := 0; split <= len(body); split++ {
			readers[fmt.Sprintf("split at %d", split)] = io.MultiReader(bytes.NewReader([]byte(body[:split])), bytes.NewReader([]byte(body[split:])))
		}
		for name, reader := range readers {
			var got bytes.Buffer
			if err := rewriteStream(&got, reader, rules); err != nil {
				t.Fatalf("%q %s: %v", body, name, err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("%q %s:\n got %q\nwant %q", body, name, got.Bytes(), want)
			}
		}
	}
}

func TestRewriteStreamReturnsTheReadError(t *testing.T) {
	failure := io.ErrUnexpectedEOF
	err := rewriteStream(io.Discard, iotest.ErrReader(failure), New("http://firewall.test").rewriteRules(config.RouteConfig{Ecosystem: "npm", PathPrefix: "/npm/"}))
	if err != failure {
		t.Fatalf("err = %v, want %v", err, failure)
	}
}

// @opencode-ai/sdk's packument is 28 MB. A 20 MiB read cap cut it off and served the
// stub with a matching Content-Length, so npm failed with "Unterminated string in JSON".
func TestProxyRewritesMetadataPastTwentyMiB(t *testing.T) {
	var body bytes.Buffer
	body.WriteString(`{"versions":{`)
	for i := 0; body.Len() < 24<<20; i++ {
		fmt.Fprintf(&body, `"1.0.%d":{"dist":{"tarball":"https://registry.npmjs.org/sdk/-/sdk-1.0.%d.tgz"}},`, i, i)
	}
	body.WriteString(`"2.0.0":{"dist":{"tarball":"https://registry.npmjs.org/sdk/-/sdk-2.0.0.tgz"}}}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
		_, _ = w.Write(body.Bytes())
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: upstream.URL + "/"}
	rec := httptest.NewRecorder()
	if _, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/npm/sdk", nil), route, registry.RequestInfo{UpstreamPath: "/sdk"}); err != nil {
		t.Fatal(err)
	}
	want := bytes.ReplaceAll(body.Bytes(), []byte("https://registry.npmjs.org/"), []byte("http://firewall.test/npm/"))
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("body = %d bytes, want %d", rec.Body.Len(), len(want))
	}
	if length := rec.Header().Get("Content-Length"); length != "" {
		t.Fatalf("Content-Length = %q; the upstream length does not survive the rewrite", length)
	}
}
