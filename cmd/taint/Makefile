.PHONY: install
install:
	@go build -o $(shell go env GOPATH)/bin/taint .

.PHONY: vhs
vhs:
	@vhs ./vhs/demo.tape
