package proxy

import (
	"bytes"
	"io"
	"strings"

	"github.com/travisjeffery/tidewaiter/internal/config"
)

// replacement points one download origin in registry metadata back at the firewall.
type replacement struct {
	old, new []byte
}

func (p *Proxy) rewriteRules(route config.RouteConfig) []replacement {
	prefix := p.baseURL + strings.TrimRight(route.PathPrefix, "/") + "/"
	switch route.Ecosystem {
	case "npm":
		return []replacement{{old: []byte("https://registry.npmjs.org/"), new: []byte(prefix)}}
	case "pypi":
		return []replacement{
			{old: []byte("https://files.pythonhosted.org/"), new: []byte(prefix + "files/")},
			{old: []byte("http://files.pythonhosted.org/"), new: []byte(prefix + "files/")},
		}
	default:
		return nil
	}
}

// rewriteStream copies src to dst with every rule applied, holding back only the
// bytes that could still start a match. The body is never held whole: npm
// packuments pass 28 MB, and the 20 MiB read cap this replaced cut them off
// mid-string and served the stub as a complete response. No old value may
// overlap another, which keeps one pass equal to applying the rules in turn.
func rewriteStream(dst io.Writer, src io.Reader, rules []replacement) error {
	keep := 0
	for _, rule := range rules {
		keep = max(keep, len(rule.old)-1)
	}
	chunk := make([]byte, 32<<10)
	pending := make([]byte, 0, len(chunk)+keep)
	for {
		n, readErr := src.Read(chunk)
		pending = append(pending, chunk[:n]...)
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		flushed, err := writeRewritten(dst, pending, rules, keep, readErr == io.EOF)
		if err != nil || readErr == io.EOF {
			return err
		}
		pending = append(pending[:0], pending[flushed:]...)
	}
}

// writeRewritten writes data with every complete match replaced and returns how
// many bytes it consumed. Unless final, it stops keep bytes short of the end so a
// match split across reads is completed by the next one.
func writeRewritten(dst io.Writer, data []byte, rules []replacement, keep int, final bool) (int, error) {
	next := make([]int, len(rules))
	for i, rule := range rules {
		next[i] = bytes.Index(data, rule.old)
	}
	start := 0
	for {
		pick := -1
		for i, at := range next {
			if at >= 0 && (pick < 0 || at < next[pick]) {
				pick = i
			}
		}
		if pick < 0 {
			break
		}
		if _, err := dst.Write(data[start:next[pick]]); err != nil {
			return 0, err
		}
		if _, err := dst.Write(rules[pick].new); err != nil {
			return 0, err
		}
		start = next[pick] + len(rules[pick].old)
		for i, at := range next {
			if at >= 0 && at < start {
				next[i] = indexFrom(data, rules[i].old, start)
			}
		}
	}
	end := len(data)
	if !final {
		end = max(start, len(data)-keep)
	}
	_, err := dst.Write(data[start:end])
	return end, err
}

func indexFrom(data, sep []byte, from int) int {
	at := bytes.Index(data[from:], sep)
	if at < 0 {
		return -1
	}
	return from + at
}
