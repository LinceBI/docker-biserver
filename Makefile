#!/usr/bin/make -f

SHELL := /bin/sh
.SHELLFLAGS := -eu -c

AWK := $(shell command -v awk 2>/dev/null)
DOCKER := $(shell command -v docker 2>/dev/null)

DISTDIR := ./dist
DOCKERFILE := ./Dockerfile
ENVFILE := $(DISTDIR)/env

IMAGE_REGISTRY := docker.io
IMAGE_NAMESPACE := stratebi
IMAGE_PROJECT := biserver
IMAGE_NAME := $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_PROJECT)
IMAGE_VERSION := 8.2.0.0-342

IMAGE_TARBALL := $(DISTDIR)/$(IMAGE_PROJECT)_$(IMAGE_VERSION)_docker.tgz
STANDALONE_TARBALL := $(DISTDIR)/$(IMAGE_PROJECT)_$(IMAGE_VERSION)_standalone.tgz

##################################################
## "all" target
##################################################

.PHONY: all
all: save-image save-standalone

##################################################
## "build-*" targets
##################################################

.PHONY: build-image
build-image:
	'$(DOCKER)' build \
		--tag '$(IMAGE_NAME):$(IMAGE_VERSION)' \
		--tag '$(IMAGE_NAME):latest' \
		--file '$(DOCKERFILE)' ./

.PHONY: build-envfile
build-envfile:
	mkdir -p '$(DISTDIR)'
	'$(AWK)' 'BEGIN {for (v in ENVIRON) {\
		gsub(/\n/, "\\n", ENVIRON[v]); \
		gsub(/\n/, "\\n", ENVIRON[v]); \
		print(v"="ENVIRON[v]); \
	}}' > '$(ENVFILE)'

##################################################
## "save-*" targets
##################################################

define save_image
	'$(DOCKER)' save '$(1)' | gzip > '$(2)'
endef

.PHONY: save-image
save-image: $(IMAGE_TARBALL)

$(IMAGE_TARBALL): build-image
	mkdir -p '$(DISTDIR)'
	$(call save_image,$(IMAGE_NAME):$(IMAGE_VERSION),$@)

.PHONY: save-standalone
save-standalone: $(STANDALONE_TARBALL)

$(STANDALONE_TARBALL): build-image build-envfile
	mkdir -p '$(DISTDIR)'
	'$(DOCKER)' run --rm --env-file '$(ENVFILE)' \
		'$(IMAGE_NAME):$(IMAGE_VERSION)' \
		/opt/scripts/export.sh > '$(STANDALONE_TARBALL)'

##################################################
## "load-*" targets
##################################################

define load_image
	'$(DOCKER)' load -i '$(1)'
endef

define tag_image
	'$(DOCKER)' tag '$(1)' '$(2)'
endef

.PHONY: load-image
load-image:
	$(call load_image,$(IMAGE_TARBALL))
	$(call tag_image,$(IMAGE_NAME):$(IMAGE_VERSION),$(IMAGE_NAME):latest)

##################################################
## "push-*" targets
##################################################

define push_image
	'$(DOCKER)' push '$(1)'
endef

.PHONY: push-image
push-image:
	@printf '%s\n' 'Unimplemented'

##################################################
## "clean" target
##################################################

.PHONY: clean
clean:
	rm -f '$(IMAGE_TARBALL)' '$(STANDALONE_TARBALL)' '$(ENVFILE)'
	if [ -d '$(DISTDIR)' ] && [ -z "$$(ls -A '$(DISTDIR)')" ]; then rmdir '$(DISTDIR)'; fi
