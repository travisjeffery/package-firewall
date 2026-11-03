package intel

import (
	"context"

	"github.com/travisjeffery/tidewaiter/internal/policy"
)

type Finding struct {
	ID       string
	Aliases  []string
	Summary  string
	Severity float64
	CWEs     []string
	// Affected and Fixed describe the ranges that apply to the queried package,
	// as written by the advisory, e.g. ">=1.2.0, <1.11.0" and "1.11.0".
	Affected []string
	Fixed    []string
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
