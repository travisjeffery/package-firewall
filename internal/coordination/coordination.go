package coordination

import (
	"context"
	"errors"
	"time"
)

var ErrLeaseLost = errors.New("coordination lease lost")

type Lease interface {
	Renew(context.Context, time.Duration) error
	Release(context.Context) error
}

type Coordinator interface {
	TryAcquire(context.Context, string, time.Duration) (Lease, bool, error)
	Cooldown(context.Context, string) (time.Time, error)
	SetCooldown(context.Context, string, time.Time) error
}
