IMAGE ?= package-firewall
TAG ?= $(shell git rev-parse --short HEAD)
PLATFORM ?= linux/arm64

AWS_REGION ?= us-east-2
# Rewrites itself to a simply-expanded value on first use, so the lookup happens
# at most once however many times the registry is composed, and not at all when
# ECR_REGISTRY is supplied or the target does not push.
AWS_ACCOUNT_ID ?= $(eval AWS_ACCOUNT_ID := $(shell aws sts get-caller-identity --query Account --output text 2>/dev/null))$(AWS_ACCOUNT_ID)
ECR_REGISTRY ?= $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ECR_REPOSITORY ?= package-firewall
# Deferred, not :=, so `make test` never resolves the account and no AWS call is
# made for a target that does not push.
ECR_IMAGE = $(ECR_REGISTRY)/$(ECR_REPOSITORY)

.PHONY: test vet live-smoke docker-build docker-build-ecr docker-push-ecr require-ecr-registry

test:
	go test ./...

vet:
	go vet ./...

live-smoke:
	./scripts/live-smoke.sh

docker-build:
	docker build --platform $(PLATFORM) -t $(IMAGE):$(TAG) .

# Checks the composed registry rather than the account, so supplying ECR_REGISTRY
# outright needs no AWS CLI at all. Without this an unauthenticated caller gets a
# registry of ".dkr.ecr...", which fails inside docker with nothing pointing at
# the cause.
require-ecr-registry:
	@case "$(ECR_REGISTRY)" in \
		""|.dkr.ecr.*) \
			echo "cannot resolve an ECR registry: set ECR_REGISTRY or AWS_ACCOUNT_ID, or authenticate the AWS CLI" >&2; \
			exit 1 ;; \
	esac

docker-build-ecr: require-ecr-registry
	docker build --platform $(PLATFORM) -t $(ECR_IMAGE):$(TAG) .

docker-push-ecr: docker-build-ecr
	docker push $(ECR_IMAGE):$(TAG)
