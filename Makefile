IMAGE ?= package-firewall
TAG ?= $(shell git rev-parse --short HEAD)
PLATFORM ?= linux/arm64

ECR_REGISTRY ?= 535528419544.dkr.ecr.us-east-2.amazonaws.com
ECR_REPOSITORY ?= package-firewall
ECR_IMAGE := $(ECR_REGISTRY)/$(ECR_REPOSITORY)

.PHONY: test vet live-smoke docker-build docker-build-ecr docker-push-ecr

test:
	go test ./...

vet:
	go vet ./...

live-smoke:
	./scripts/live-smoke.sh

docker-build:
	docker build --platform $(PLATFORM) -t $(IMAGE):$(TAG) .

docker-build-ecr:
	docker build --platform $(PLATFORM) -t $(ECR_IMAGE):$(TAG) .

docker-push-ecr: docker-build-ecr
	docker push $(ECR_IMAGE):$(TAG)
