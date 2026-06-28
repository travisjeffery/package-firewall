package intel

import (
	"context"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

type Finding struct {
	ID       string
	Summary  string
	Severity float64
}

type Result struct {
	Findings []Finding
}

type Provider interface {
	Query(ctx context.Context, pkg policy.Package) (Result, error)
}

type NoopProvider struct{}

func (NoopProvider) Query(context.Context, policy.Package) (Result, error) {
	return Result{}, nil
}
