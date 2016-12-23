#!/bin/bash
# Make sure GOPATH is strictly to local
export GOPATH=$(pwd)

# Make sure GOBIN is local, so it'll build it to local workspace
export GOBIN=$(pwd)/bin

# If using $GOPATH/vendor path, don't do this below:
#go get -u golang.org/x/tools/go/loader

# No need to do this all the time, it takes longer
#make vendor_get

go fmt -x iptablesConverter/...
go test -v iptablesConverter/...
go install -v iptablesConverter/...

#go env
#tree -I "vendor|_vendor"
#tree pkg
