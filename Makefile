#!/usr/bin/make -f

SHELL := /bin/sh
.SHELLFLAGS := -eu -c

AWK := $(shell command -v awk 2>/dev/null)
DOCKER := $(shell command -v docker 2>/dev/null)

DISTDIR := ./dist
DOCKERFILE := ./Dockerfile

IMAGE_REGISTRY := repo.stratebi.com
IMAGE_NAMESPACE := lincebi
IMAGE_PROJECT := biserver
IMAGE_NAME := $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_PROJECT)
IMAGE_VERSION := 9.0.0.0-423

IMAGE_BUILD_OPTS :=

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
		--file '$(DOCKERFILE)' $(IMAGE_BUILD_OPTS) ./

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

$(STANDALONE_TARBALL): build-image
	mkdir -p '$(DISTDIR)'
	'$(DOCKER)' run --rm \
		'$(IMAGE_NAME):$(IMAGE_VERSION)' \
		/usr/share/biserver/bin/export.sh > '$(STANDALONE_TARBALL)'

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

##################################################
## "push-*" targets
##################################################

define push_image
	'$(DOCKER)' push '$(1)'
endef

.PHONY: push-image
push-image:
	$(call push_image,$(IMAGE_NAME):$(IMAGE_VERSION))

##################################################
## "clean" target
##################################################

.PHONY: clean
clean:
	rm -f '$(IMAGE_TARBALL)' '$(STANDALONE_TARBALL)'
	if [ -d '$(DISTDIR)' ] && [ -z "$$(ls -A '$(DISTDIR)')" ]; then rmdir '$(DISTDIR)'; fi
