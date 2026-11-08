.PHONY: build test install clean

build:
	go build -o bin/airgap-check ./cmd/airgap-check

test:
	go test -v ./...

install:
	go install ./cmd/airgap-check

clean:
	rm -rf bin/
