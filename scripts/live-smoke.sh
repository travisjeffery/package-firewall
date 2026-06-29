#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
PFW_LIVE=1 go test ./test/live -run 'TestLive(KubernetesDependencies|BlocksDeniedKubernetesDependency)' -count=1 -v "$@"
