.PHONY: build doc fmt lint run test vendor_clean vendor_get vendor_update vet

# Prepend our vendor directory to the system GOPATH
# so that import path resolution will prioritize
# our third party snapshots.
GOPATH := ${PWD}/vendor:${GOPATH}
export GOPATH

default: build

build: vet
	go build -race -v iptablesConverter/...

doc:
	godoc -http=:6060 -index

# http://golang.org/cmd/go/#hdr-Run_gofmt_on_package_sources
fmt:
	go fmt iptablesConverter/...

# https://github.com/golang/lint
# go get github.com/golang/lint/golint
lint:
	#${GOROOT}/bin/golint ./src/iptablesConverter/...
	${GOROOT}/bin/gometalinter src/iptablesConverter/... > /tmp/lint.tmp 2>/dev/null ; \
	cat /tmp/lint.tmp ; \
	rm /tmp/lint.tmp

run: build
	./bin/iptables2nftables

test:
	go test -v iptablesConverter/...

vendor_clean:
	rm -dRf ./vendor/src

# We have to set GOPATH to just the vendor
# directory to ensure that `go get` doesn't
# update packages in our primary GOPATH instead.
# This will happen if you already have the package
# installed in GOPATH since `go get` will use
# that existing location as the destination.
vendor_get: vendor_clean
	GOPATH=${PWD}/vendor go get -d -u -v \
	github.com/jpoehls/gophermail \
	github.com/codegangsta/martini

vendor_update: vendor_get
	rm -rf `find ./vendor/src -type d -name .git` \
	&& rm -rf `find ./vendor/src -type d -name .hg` \
	&& rm -rf `find ./vendor/src -type d -name .bzr` \
	&& rm -rf `find ./vendor/src -type d -name .svn`

# http://godoc.org/code.google.com/p/go.tools/cmd/vet
# go get code.google.com/p/go.tools/cmd/vet
vet:
	go vet -v -x iptablesConverter/...
	go tool vet -v -shadowstrict src/iptablesConverter
