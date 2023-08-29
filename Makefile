#!/usr/bin/make -f

SHELL := /bin/sh
.SHELLFLAGS := -euc

AWK := $(shell command -v awk 2>/dev/null)
DOCKER := $(shell command -v docker 2>/dev/null)

DISTDIR := ./dist
DOCKERFILE := ./Dockerfile

IMAGE_REGISTRY := repo.stratebi.com
IMAGE_NAMESPACE := lincebi
IMAGE_PROJECT := biserver
IMAGE_NAME := $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_PROJECT)
IMAGE_VERSION := 9.3.0.5-753-1
# Extract <MAJOR>.<MINOR> from <MAJOR>.<MINOR>.<MAINTENANCE>.<SERVICEPACK>-<BUILD>-<IMGREL>
IMAGE_VERSION_MINOR := $(shell awk -v v='$(IMAGE_VERSION)' 'BEGIN{match(v,/^[0-9]+\.[0-9]+/);print(substr(v,RSTART,RLENGTH))}')

IMAGE_BUILD_OPTS :=

IMAGE_TARBALL := $(DISTDIR)/$(IMAGE_PROJECT)_$(IMAGE_VERSION)_docker.tzst
STANDALONE_ARCHIVE := $(DISTDIR)/$(IMAGE_PROJECT)_$(IMAGE_VERSION)_standalone.zip

export DOCKER_BUILDKIT := 1
export BUILDKIT_PROGRESS := plain

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
		--tag '$(IMAGE_NAME):$(IMAGE_VERSION_MINOR)' \
		--file '$(DOCKERFILE)' $(IMAGE_BUILD_OPTS) ./

##################################################
## "save-*" targets
##################################################

define save_image
	'$(DOCKER)' save '$(1)' | zstd -T0 -1 > '$(2)'
endef

.PHONY: save-image
save-image: $(IMAGE_TARBALL)

$(IMAGE_TARBALL): build-image
	mkdir -p '$(DISTDIR)'
	$(call save_image,$(IMAGE_NAME):$(IMAGE_VERSION),$@)

.PHONY: save-standalone
save-standalone: $(STANDALONE_ARCHIVE)

$(STANDALONE_ARCHIVE): build-image
	mkdir -p '$(DISTDIR)'
	'$(DOCKER)' run --rm \
		--env DEFAULT_ADMIN_PASSWORD='password' \
		'$(IMAGE_NAME):$(IMAGE_VERSION)' \
		/usr/share/biserver/bin/export.sh > '$(STANDALONE_ARCHIVE)'

##################################################
## "load-*" targets
##################################################

define load_image
	zstd -dc '$(1)' | '$(DOCKER)' load
endef

define tag_image
	'$(DOCKER)' tag '$(1)' '$(2)'
endef

.PHONY: load-image
load-image:
	$(call load_image,$(IMAGE_TARBALL))
	$(call tag_image,$(IMAGE_NAME):$(IMAGE_VERSION),$(IMAGE_NAME):$(IMAGE_VERSION_MINOR))

##################################################
## "push-*" targets
##################################################

define push_image
	'$(DOCKER)' push '$(1)'
endef

.PHONY: push-image
push-image:
	$(call push_image,$(IMAGE_NAME):$(IMAGE_VERSION))
	$(call push_image,$(IMAGE_NAME):$(IMAGE_VERSION_MINOR))

##################################################
## "clean" target
##################################################

.PHONY: clean
clean:
	rm -f '$(IMAGE_TARBALL)' '$(STANDALONE_ARCHIVE)'
	if [ -d '$(DISTDIR)' ] && [ -z "$$(ls -A '$(DISTDIR)')" ]; then rmdir '$(DISTDIR)'; fi
