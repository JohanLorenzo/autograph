all: lint vet test build

build:
	go build -o autograph-edge *.go
	zip -r autograph-edge.zip autograph-edge autograph-edge.yaml
test:
	go test go.mozilla.org/autograph/tools/autograph-edge
lint:
	golint *.go
vet:
	go vet *.go
clean:
	rm autograph-edge autograph-edge.zip
.PHONY: vendor clean build
