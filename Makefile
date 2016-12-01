# Copyright 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Use the native vendor/ dependency system
export GO15VENDOREXPERIMENT=1

# Bump this on release
VERSION ?= v0.0.1

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
BUILD_DIR ?= ./out
ORG := github.com/jimmidyson
REPOPATH ?= $(ORG)/pemtokeystore
DOCKER_IMAGE_NAME ?= jimmidyson/pemtokeystore
DOCKER_IMAGE_TAG ?= latest

LDFLAGS := -s -w -extldflags '-static'

SRCFILES := go list  -f '{{join .Deps "\n"}}' ./cmd/pemtokeystore/main.go | grep $(REPOPATH) | xargs go list -f '{{ range $$file := .GoFiles }} {{$$.Dir}}/{{$$file}}{{"\n"}}{{end}}'

out/pemtokeystore: out/pemtokeystore-$(GOOS)-$(GOARCH)
	cp $(BUILD_DIR)/pemtokeystore-$(GOOS)-$(GOARCH) $(BUILD_DIR)/pemtokeystore

out/pemtokeystore-darwin-amd64: ./cmd/pemtokeystore/main.go $(shell $(SRCFILES))
	cd $(GOPATH)/src/$(REPOPATH) && CGO_ENABLED=0 GOARCH=amd64 GOOS=darwin go build --installsuffix cgo -ldflags="$(LDFLAGS)" -a -o $(BUILD_DIR)/pemtokeystore-darwin-amd64 ./cmd/pemtokeystore/main.go

out/pemtokeystore-linux-amd64: ./cmd/pemtokeystore/main.go $(shell $(SRCFILES))
	cd $(GOPATH)/src/$(REPOPATH) && CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build --installsuffix cgo -ldflags="$(LDFLAGS)" -a -o $(BUILD_DIR)/pemtokeystore-linux-amd64 ./cmd/pemtokeystore/main.go

out/pemtokeystore-windows-amd64.exe: ./cmd/pemtokeystore/main.go $(shell $(SRCFILES))
	cd $(GOPATH)/src/$(REPOPATH) && CGO_ENABLED=0 GOARCH=amd64 GOOS=windows go build --installsuffix cgo -ldflags="$(LDFLAGS)" -a -o $(BUILD_DIR)/pemtokeystore-windows-amd64.exe ./cmd/pemtokeystore/main.go

.PHONY: cross
cross: out/pemtokeystore-linux-amd64 out/pemtokeystore-darwin-amd64 out/pemtokeystore-windows-amd64.exe

.PHONY: checksum
checksum:
	for f in out/pemtokeystore-linux-amd64 out/pemtokeystore-darwin-amd64 out/pemtokeystore-windows-amd64.exe ; do \
		if [ -f "$${f}" ]; then \
			openssl sha256 "$${f}" | awk '{print $$2}' > "$${f}.sha256" ; \
		fi ; \
	done

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf testdata/*.csr testdata/*.json testdata/*.pem testdata/.created testdata/*.class testdata/*.ks*

.PHONY: docker
docker: out/pemtokeystore Dockerfile
	docker build -t $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) .

.PHONY: test
test: create-test-certs
	go test -race .

.PHONY: create-test-certs
create-test-certs: testdata/.created

testdata/.created: testdata/create-certs.sh
	testdata/create-certs.sh
	touch testdata/.created


