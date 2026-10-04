# Kerberos Diamond
#
# Quick start:
#   make certs db-up run      run the KDC on the host
#   make pod-build pod-run    run it in a container
#
# Override any variable on the command line, e.g.
#   make run KDC_PORT=9088

BINARY      := kdiamond
PROXY_BIN   := kdiamond-proxy
IMAGE       ?= localhost/kdiamond
PROXY_IMAGE ?= localhost/kdiamond-proxy
TAG         ?= dev
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null \
                 || echo dev)

# Where the TLS material lives. There is no cleartext listener, so the
# KDC will not start without it.
TLS_DIR     ?= deploy/tls
CERT_FILE   := $(TLS_DIR)/cert.pem
KEY_FILE    := $(TLS_DIR)/key.pem
CERT_CN     ?= localhost
CERT_DAYS   ?= 365

# The KDC's listener. Kerberos' assigned port is 88, which rootless
# Podman cannot bind; under KKDCP the KDC is reached by URL anyway, so
# there is nothing to gain by insisting on it.
KDC_PORT    ?= 8088
PROXY_PATH  ?= KdcProxy
REALM       ?= KDIAMOND.TEST

# Postgres, run as a container for local work.
DB_NAME     ?= kdiamond
# Tests get a database of their own. They isolate themselves into a
# scratch schema as well, but keeping the databases apart means a bug
# in that isolation costs nothing.
TEST_DB_NAME?= kdiamond_test
DB_USER     ?= kdiamond
DB_PASSWORD ?= kdiamond
# Not 5432: a developer's own Postgres commonly has that, and a
# container silently shadowing it is a bad afternoon.
DB_PORT     ?= 55433
DB_IMAGE    ?= docker.io/library/postgres:17-alpine
PG_CONTAINER:= kdiamond-pg
PG_VOLUME   := kdiamond-pgdata
NETWORK     ?= kdiamond

# From inside a container Postgres is reached by its container name;
# from the host, by the published port.
DB_URL      ?= postgres://$(DB_USER):$(DB_PASSWORD)@localhost:$(DB_PORT)/$(DB_NAME)?sslmode=disable
DB_URL_POD  := postgres://$(DB_USER):$(DB_PASSWORD)@$(PG_CONTAINER):5432/$(DB_NAME)?sslmode=disable
TEST_DB_URL := postgres://$(DB_USER):$(DB_PASSWORD)@localhost:$(DB_PORT)/$(TEST_DB_NAME)?sslmode=disable

APP_CONTAINER := kdiamond

# The distroless base runs as the unprivileged "nonroot" user.
# Rootless Podman maps that to a subordinate uid on the host, which
# cannot read a private key owned by you with the usual 0600
# permissions. Mapping your uid onto it makes the container process
# *be* you, so the key stays 0600 and still opens.
NONROOT_UID := 65532
USERNS      ?= keep-id:uid=$(NONROOT_UID),gid=$(NONROOT_UID)

GO          ?= go
GOFLAGS     ?=
LDFLAGS     := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@echo "Kerberos Diamond"
	@echo
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / \
		{printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}' \
		$(MAKEFILE_LIST)
	@echo
	@echo "  Database: $(DB_URL)"
	@echo "  Tests:    $(TEST_DB_URL)"
	@echo "  TLS:      $(TLS_DIR)"

# --- building ---------------------------------------------------------

.PHONY: build
build: ## Build the KDC binary
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" \
		-o $(BINARY) ./cmd/kdiamond

.PHONY: build-proxy
build-proxy: ## Build the client-side KKDCP proxy
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" \
		-o $(PROXY_BIN) ./cmd/kdiamond-proxy

.PHONY: all
all: build build-proxy ## Build both binaries

.PHONY: clean
clean: ## Remove build artefacts
	rm -f $(BINARY) $(PROXY_BIN) coverage.out coverage.html
	rm -rf build

.PHONY: distclean
distclean: clean pod-clean ## Remove artefacts and containers
	@echo "$(TLS_DIR) was left alone; remove it by hand if you mean to."

# --- testing ----------------------------------------------------------

# The store tests need a database and skip without one. They are
# pointed at a database of their own, never one holding real data.
#
# An already-set KD_TEST_DATABASE_URL is honoured and no container is
# started, so CI can hand this a service database and still run the
# same target a developer runs.
.PHONY: test
test: ## Run the tests (starts Postgres unless one is given)
	@if [ -z "$$KD_TEST_DATABASE_URL" ]; then \
		$(MAKE) --no-print-directory db-up; \
	fi
	KD_TEST_DATABASE_URL="$${KD_TEST_DATABASE_URL:-$(TEST_DB_URL)}" \
		$(GO) test -race ./...

.PHONY: test-short
test-short: ## Run only the tests that need no database
	$(GO) test ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

# --- formatting -------------------------------------------------------

# gofmt does not wrap anything, so the 70-column rule needs a second
# pass. tools/reflow does the parts a line-wrapper cannot: it reflows
# comment *paragraphs* rather than single lines, moves one-line
# function bodies out, splits composite literals a field per line, and
# breaks long conditions after their operators.
#
# kerberos/ is excluded throughout: it is upstream's C, read-only.
GOSRC = find . -name '*.go' -not -path './kerberos/*' -print0

.PHONY: fmt
fmt: ## Format Go source and rewrap comments to 70 columns
	@$(GOSRC) | xargs -0 gofmt -w
	@$(GO) run ./tools/reflow -w .
	@$(GOSRC) | xargs -0 gofmt -w

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is unformatted
	@out=$$($(GOSRC) | xargs -0 gofmt -l); \
	if [ -n "$$out" ]; then \
		echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@$(GO) run ./tools/reflow -l . >/dev/null \
		|| { echo "run 'make fmt': comments need rewrapping"; \
		     exit 1; }

# width-check holds the 70-column rule. The whole tree meets it, so
# this can be run over everything — and is, by `make check'. RANGE
# narrows it to one commit range instead, which is what CI wants:
#
#   make width-check RANGE=HEAD~1..HEAD
RANGE ?=

.PHONY: width-check
width-check: ## Fail if any Go line exceeds 70 columns (RANGE=...)
	@if [ -n "$(RANGE)" ]; then \
		long=$$(git diff --unified=0 $(RANGE) -- '*.go' \
			| grep -E '^\+[^+]' | sed 's/^+//' \
			| expand -t8 | awk 'length > 70'); \
		where="added in $(RANGE)"; \
	else \
		long=$$($(GOSRC) | xargs -0 -I{} sh -c \
			'expand -t8 "{}" \
			 | awk -v f="{}" "length > 70 \
			   {print f\":\"FNR\": \"\$$0}"'); \
		where="in the tree"; \
	fi; \
	if [ -n "$$long" ]; then \
		echo "these lines exceed 70 columns (tab=8), $$where:"; \
		echo "$$long"; exit 1; fi
	@echo "no Go lines over 70 columns"

.PHONY: check
check: vet fmt-check width-check test ## Vet, check formatting, and test

.PHONY: cover
cover: ## Write an HTML coverage report
	@if [ -z "$$KD_TEST_DATABASE_URL" ]; then \
		$(MAKE) --no-print-directory db-up; \
	fi
	KD_TEST_DATABASE_URL="$${KD_TEST_DATABASE_URL:-$(TEST_DB_URL)}" \
		$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

# --- TLS --------------------------------------------------------------

.PHONY: certs
certs: $(KEY_FILE) ## Generate a self-signed certificate for local use

$(KEY_FILE):
	@mkdir -p $(TLS_DIR)
	openssl req -x509 -newkey rsa:4096 -nodes -days $(CERT_DAYS) \
		-subj "/CN=$(CERT_CN)" \
		-addext "subjectAltName=DNS:$(CERT_CN),DNS:localhost,IP:127.0.0.1" \
		-keyout $(KEY_FILE) -out $(CERT_FILE)
	@chmod 600 $(KEY_FILE)
	@echo "wrote $(CERT_FILE) and $(KEY_FILE)"
	@echo "(self-signed, for local use only)"

# --- database ---------------------------------------------------------

# A transient host-port collision can happen while another process or
# container is releasing the port. Only that specific class of
# podman-run failure is retried; other startup errors fail at once.
#
# The pattern deliberately does not match a bare `bind:'. Podman
# reports the collision as "rootlessport listen tcp 0.0.0.0:55433:
# bind: address already in use", so `address already in use' — the
# kernel's own EADDRINUSE wording, and the stable half of that line —
# already catches it. What `bind:' would add is the bind failures that
# never clear by waiting, `bind: permission denied' and `bind: cannot
# assign requested address', each of which would then stall for the
# whole retry budget before failing anyway.
#
# The delay is short and the retries many on purpose. What is being
# waited for is a *listening* socket released by a dying rootlessport
# helper, and a listening socket does not go through TIME_WAIT — so
# the window is seconds, and a long first delay turns a two-second
# hiccup into a long stall. `make check' starts Postgres, so this sits
# under the command run most often. DB_BIND_RETRIES=1 is "do not
# retry"; 0 would start nothing at all.
DB_BIND_RETRIES     ?= 10
DB_BIND_RETRY_DELAY ?= 3

.PHONY: db-up
db-up: ## Start Postgres and wait for it
	@if [ -z "$$(podman ps -q -f name=^$(PG_CONTAINER)$$)" ]; then \
		podman network exists $(NETWORK) \
			|| podman network create $(NETWORK) >/dev/null; \
		podman rm -f $(PG_CONTAINER) >/dev/null 2>&1 || true; \
		for attempt in $$(seq 1 $(DB_BIND_RETRIES)); do \
			echo "starting Postgres..."; \
			if output=$$(podman run -d \
				--name $(PG_CONTAINER) \
				--network $(NETWORK) \
				-e POSTGRES_USER=$(DB_USER) \
				-e POSTGRES_PASSWORD=$(DB_PASSWORD) \
				-e POSTGRES_DB=$(DB_NAME) \
				-p $(DB_PORT):5432 \
				-v $(PG_VOLUME):/var/lib/postgresql/data \
				$(DB_IMAGE) 2>&1); then \
				break; \
			fi; \
			echo "Postgres failed to start:"; \
			echo "$$output"; \
			if ! echo "$$output" | grep -Eqi \
				'address already in use|unable to bind|cannot bind|cannot listen on.*port'; then \
				exit 1; \
			fi; \
			if [ "$$attempt" -eq "$(DB_BIND_RETRIES)" ]; then \
				echo "port binding failed after $(DB_BIND_RETRIES) attempts"; \
				exit 1; \
			fi; \
			echo "port binding failed; retrying in $(DB_BIND_RETRY_DELAY)s..."; \
			podman rm -f $(PG_CONTAINER) >/dev/null 2>&1 || true; \
			sleep $(DB_BIND_RETRY_DELAY); \
		done; \
		for i in $$(seq 1 60); do \
			podman exec $(PG_CONTAINER) psql \
				-h 127.0.0.1 -p 5432 \
				-U $(DB_USER) -d postgres -tAc "SELECT 1" \
				>/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		podman exec $(PG_CONTAINER) psql \
			-h 127.0.0.1 -p 5432 \
			-U $(DB_USER) -d postgres -tAc "SELECT 1" \
			>/dev/null 2>&1 \
			|| { echo "Postgres did not become ready"; \
			     podman logs $(PG_CONTAINER) 2>&1 | tail -50; \
			     exit 1; }; \
		echo "Postgres is ready on port $(DB_PORT)"; \
	fi
	@podman exec $(PG_CONTAINER) psql \
		-h 127.0.0.1 -p 5432 \
		-U $(DB_USER) -d postgres -tAc \
		"SELECT 1 FROM pg_database WHERE datname='$(TEST_DB_NAME)'" \
		| grep -q 1 \
		|| podman exec $(PG_CONTAINER) createdb \
			-h 127.0.0.1 -p 5432 \
			-U $(DB_USER) $(TEST_DB_NAME)

.PHONY: db-down
db-down: ## Stop Postgres, keeping its data
	-podman rm -f $(PG_CONTAINER) 2>/dev/null

.PHONY: db-reset
db-reset: ## Destroy the database and everything in it
	-podman rm -f $(PG_CONTAINER) 2>/dev/null
	-podman volume rm $(PG_VOLUME) 2>/dev/null
	@echo "database destroyed"

.PHONY: psql
psql: db-up ## Open a psql shell
	podman exec -it $(PG_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME)

# --- running on the host ----------------------------------------------

.PHONY: run
run: build certs db-up ## Run the KDC on the host
	KD_DATABASE_URL="$(DB_URL)" \
	KD_REALM="$(REALM)" \
	KD_LISTEN_ADDR=":$(KDC_PORT)" \
	KD_PROXY_PATH="$(PROXY_PATH)" \
	KD_TLS_CERT_FILE=$(CERT_FILE) \
	KD_TLS_KEY_FILE=$(KEY_FILE) \
	./$(BINARY) serve

# --- the golden-output oracle -----------------------------------------

# Kerberos 5 built from the C sources in the kerberos submodule. The
# golden tests run the same exchange against it and against this KDC,
# and compare the two.
ORACLE_IMAGE ?= localhost/krb5-oracle
ORACLE_SRC   ?= kerberos

.PHONY: golden-build
golden-build: $(ORACLE_SRC)/src ## Build the C Kerberos 5 to compare against
	@echo "staging $(ORACLE_SRC)..."
	@rm -rf build/oracle && mkdir -p build/oracle
	@git -C $(ORACLE_SRC) archive HEAD | tar -x -C build/oracle
	@cp deploy/golden/Containerfile.krb5 build/oracle/
	podman build -t $(ORACLE_IMAGE) \
		-f build/oracle/Containerfile.krb5 build/oracle
	@rm -rf build/oracle

# The upstream C is a submodule; the oracle is the only thing that
# builds it.
$(ORACLE_SRC)/src:
	git submodule update --init $(ORACLE_SRC)

.PHONY: golden
golden: ## Run the differential tests against the C KDC
	@podman image exists $(ORACLE_IMAGE) \
		|| { echo "the oracle is not built; run 'make golden-build'"; \
		     exit 1; }
	$(GO) test -v -count=1 ./internal/golden/

.PHONY: golden-clean
golden-clean: ## Remove the oracle image
	-podman rmi -f $(ORACLE_IMAGE) 2>/dev/null

# --- running in a container -------------------------------------------

PUBLISH_DATE  := $(shell date +%Y%m%d)
PUBLISH_IMAGE ?= ghcr.io/fatmanuk/kerberos_diamond
PROXY_PUBLISH_IMAGE ?= ghcr.io/fatmanuk/kdiamond_proxy

.PHONY: pod-build
pod-build: ## Build the KDC container image
	podman build --build-arg VERSION=$(VERSION) --target kdc \
		-t $(IMAGE):$(TAG) -f deploy/Containerfile .

.PHONY: pod-proxy-build
pod-proxy-build: ## Build the proxy container image
	podman build --build-arg VERSION=$(VERSION) --target proxy \
		-t $(PROXY_IMAGE):$(TAG) -f deploy/Containerfile .

.PHONY: pod-push
pod-push: pod-build ## Push the KDC container image
	podman tag $(IMAGE):$(TAG) $(PUBLISH_IMAGE):latest
	podman push $(PUBLISH_IMAGE):latest
	podman tag $(IMAGE):$(TAG) $(PUBLISH_IMAGE):$(VERSION)
	podman push $(PUBLISH_IMAGE):$(VERSION)
	podman tag $(IMAGE):$(TAG) $(PUBLISH_IMAGE):$(PUBLISH_DATE)
	podman push $(PUBLISH_IMAGE):$(PUBLISH_DATE)
	podman tag $(IMAGE):$(TAG) $(PUBLISH_IMAGE):$(TAG)
	podman push $(PUBLISH_IMAGE):$(TAG)

.PHONY: pod-run
pod-run: pod-build certs db-up ## Run the KDC in a container
	@podman network exists $(NETWORK) \
		|| podman network create $(NETWORK) >/dev/null
	@podman rm -f $(APP_CONTAINER) >/dev/null 2>&1 || true
	podman run -d --name $(APP_CONTAINER) \
		--network $(NETWORK) \
		--userns=$(USERNS) \
		-p $(KDC_PORT):8088 \
		-e KD_DATABASE_URL="$(DB_URL_POD)" \
		-e KD_REALM="$(REALM)" \
		-e KD_TLS_CERT_FILE=/etc/kdiamond/tls/cert.pem \
		-e KD_TLS_KEY_FILE=/etc/kdiamond/tls/key.pem \
		-v ./$(TLS_DIR):/etc/kdiamond/tls:ro,z \
		$(IMAGE):$(TAG) serve
	@echo "waiting for the KDC..."
	@for i in $$(seq 1 30); do \
		podman logs $(APP_CONTAINER) 2>&1 \
			| grep -q 'listening' && break; \
		podman ps -q -f name=^$(APP_CONTAINER)$$ | grep -q . \
			|| { echo "the container exited:"; \
			     podman logs $(APP_CONTAINER); exit 1; }; \
		sleep 1; \
	done
	@podman logs $(APP_CONTAINER) 2>&1 | tail -5
	@echo
	@echo "KDC on https://127.0.0.1:$(KDC_PORT)/$(PROXY_PATH)"

.PHONY: pod-logs
pod-logs: ## Follow the KDC container's logs
	podman logs -f $(APP_CONTAINER)

.PHONY: pod-stop
pod-stop: ## Stop the KDC container
	-podman rm -f $(APP_CONTAINER) 2>/dev/null

.PHONY: pod-clean
pod-clean: pod-stop db-down ## Remove containers, images and the network
	-podman rmi -f $(IMAGE):$(TAG) 2>/dev/null
	-podman rmi -f $(PROXY_IMAGE):$(TAG) 2>/dev/null
	-podman network rm $(NETWORK) 2>/dev/null
