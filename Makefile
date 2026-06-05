.PHONY: test test-core test-tags fmt tidy check docs

GO_PACKAGES := ./pkg/...
CORE_PACKAGES := ./pkg/crypto ./pkg/proof ./pkg/transaction ./pkg/events ./pkg/wallet ./pkg/quicksync ./pkg/sdk

test:
	go test $(GO_PACKAGES)

test-core:
	go test $(CORE_PACKAGES)

test-tags:
	go test -tags witnesscalc ./pkg/proof/witness

fmt:
	gofmt -w $$(find pkg -name '*.go' -type f)

tidy:
	go mod tidy

check:
	go test $(GO_PACKAGES)
	git diff --check -- .

docs:
	go doc ./pkg/sdk
	go doc ./pkg/sdk Runtime
	go doc ./pkg/sdk SyncStrategy
