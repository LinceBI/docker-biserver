#!/usr/bin/make -f

SHELL := /bin/sh
.SHELLFLAGS := -euc

AWK := $(shell command -v awk 2>/dev/null)
DOCKER := $(shell command -v docker 2>/dev/null)
M4 := $(shell command -v m4 2>/dev/null)

DISTDIR := ./dist
DOCKERFILE_TEMPLATE := ./Dockerfile.m4

IMAGE_REGISTRY := repo.stratebi.com
IMAGE_NAMESPACE := lincebi
IMAGE_PROJECT := biserver
IMAGE_NAME := $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/$(IMAGE_PROJECT)
IMAGE_VERSION := 9.3.0.10-886-2
# Extract <MAJOR>.<MINOR> from <MAJOR>.<MINOR>.<MAINTENANCE>.<SERVICEPACK>-<BUILD>-<IMGREL>
IMAGE_VERSION_MINOR := $(shell awk -v v='$(IMAGE_VERSION)' 'BEGIN{match(v,/^[0-9]+\.[0-9]+/);print(substr(v,RSTART,RLENGTH))}')

IMAGE_BUILD_OPTS :=

IMAGE_NATIVE_DOCKERFILE := $(DISTDIR)/Dockerfile
IMAGE_NATIVE_TARBALL := $(DISTDIR)/$(IMAGE_PROJECT)_docker.tzst
STANDALONE_ARCHIVE := $(DISTDIR)/$(IMAGE_PROJECT)_$(IMAGE_VERSION)_standalone.zip
IMAGE_AMD64_DOCKERFILE := $(DISTDIR)/Dockerfile.amd64
IMAGE_AMD64_TARBALL := $(DISTDIR)/$(IMAGE_PROJECT)_docker.amd64.tzst
STANDALONE_AMD64_ARCHIVE := $(DISTDIR)/$(IMAGE_PROJECT)_$(IMAGE_VERSION)_standalone.amd64.zip
IMAGE_ARM64V8_DOCKERFILE := $(DISTDIR)/Dockerfile.arm64v8
IMAGE_ARM64V8_TARBALL := $(DISTDIR)/$(IMAGE_PROJECT)_docker.arm64v8.tzst
STANDALONE_ARM64V8_ARCHIVE := $(DISTDIR)/$(IMAGE_PROJECT)_$(IMAGE_VERSION)_standalone.arm64v8.zip

export DOCKER_BUILDKIT := 1
export BUILDKIT_PROGRESS := plain

##################################################
## "all" target
##################################################

.PHONY: all
all: save-native-image

##################################################
## "build-*" targets
##################################################

.PHONY: build-native-image
build-native-image: $(IMAGE_NATIVE_DOCKERFILE)

$(IMAGE_NATIVE_DOCKERFILE): $(DOCKERFILE_TEMPLATE)
	mkdir -p '$(DISTDIR)'
	'$(M4)' \
		--prefix-builtins \
		'$(DOCKERFILE_TEMPLATE)' > '$@'
	'$(DOCKER)' build \
		--tag '$(IMAGE_NAME):$(IMAGE_VERSION)' \
		--tag '$(IMAGE_NAME):$(IMAGE_VERSION_MINOR)' \
		--file '$@' $(IMAGE_BUILD_OPTS) ./

.PHONY: build-cross-images
build-cross-images: build-amd64-image build-arm64v8-image

.PHONY: build-amd64-image
build-amd64-image: $(IMAGE_AMD64_DOCKERFILE)

$(IMAGE_AMD64_DOCKERFILE): $(DOCKERFILE_TEMPLATE)
	mkdir -p '$(DISTDIR)'
	'$(M4)' \
		--prefix-builtins \
		--define=CROSS_ARCH=amd64 \
		'$(DOCKERFILE_TEMPLATE)' > '$@'
	'$(DOCKER)' build \
		--tag '$(IMAGE_NAME):$(IMAGE_VERSION)-amd64' \
		--tag '$(IMAGE_NAME):$(IMAGE_VERSION_MINOR)-amd64' \
		--platform linux/amd64 \
		--file '$@' $(IMAGE_BUILD_OPTS) ./

.PHONY: build-arm64v8-image
build-arm64v8-image: $(IMAGE_ARM64V8_DOCKERFILE)

$(IMAGE_ARM64V8_DOCKERFILE): $(DOCKERFILE_TEMPLATE)
	mkdir -p '$(DISTDIR)'
	'$(M4)' \
		--prefix-builtins \
		--define=CROSS_ARCH=arm64v8 \
		'$(DOCKERFILE_TEMPLATE)' > '$@'
	'$(DOCKER)' build \
		--tag '$(IMAGE_NAME):$(IMAGE_VERSION)-arm64v8' \
		--tag '$(IMAGE_NAME):$(IMAGE_VERSION_MINOR)-arm64v8' \
		--platform linux/arm64/v8 \
		--file '$@' $(IMAGE_BUILD_OPTS) ./

##################################################
## "save-*" targets
##################################################

define save_image
	'$(DOCKER)' save '$(1)' | zstd -T0 > '$(2)'
endef

.PHONY: save-native-image
save-native-image: $(IMAGE_NATIVE_TARBALL)

$(IMAGE_NATIVE_TARBALL): $(IMAGE_NATIVE_DOCKERFILE)
	mkdir -p '$(DISTDIR)'
	$(call save_image,$(IMAGE_NAME):$(IMAGE_VERSION),$@)

.PHONY: save-cross-images
save-cross-images: save-amd64-image save-arm64v8-image

.PHONY: save-amd64-image
save-amd64-image: $(IMAGE_AMD64_TARBALL)

$(IMAGE_AMD64_TARBALL): $(IMAGE_AMD64_DOCKERFILE)
	$(call save_image,$(IMAGE_NAME):$(IMAGE_VERSION)-amd64,$@)

.PHONY: save-arm64v8-image
save-arm64v8-image: $(IMAGE_ARM64V8_TARBALL)

$(IMAGE_ARM64V8_TARBALL): $(IMAGE_ARM64V8_DOCKERFILE)
	$(call save_image,$(IMAGE_NAME):$(IMAGE_VERSION)-arm64v8,$@)

.PHONY: save-standalone
save-standalone: $(STANDALONE_ARCHIVE)

$(STANDALONE_ARCHIVE): $(IMAGE_DOCKERFILE)
	mkdir -p '$(DISTDIR)'
	'$(DOCKER)' run --rm \
		--env DEFAULT_ADMIN_PASSWORD='password' \
		'$(IMAGE_NAME):$(IMAGE_VERSION)' \
		/usr/share/biserver/bin/export.sh > '$(STANDALONE_ARCHIVE)'

.PHONY: save-cross-standalone
save-cross-standalone: save-amd64-standalone save-arm64v8-standalone

.PHONY: save-amd64-standalone
save-amd64-standalone: $(STANDALONE_AMD64_ARCHIVE)

$(STANDALONE_AMD64_ARCHIVE): $(IMAGE_AMD64_DOCKERFILE)
	mkdir -p '$(DISTDIR)'
	'$(DOCKER)' run --rm \
		--env DEFAULT_ADMIN_PASSWORD='password' \
		'$(IMAGE_NAME):$(IMAGE_VERSION)-amd64' \
		/usr/share/biserver/bin/export.sh > '$(STANDALONE_AMD64_ARCHIVE)'

.PHONY: save-arm64v8-standalone
save-arm64v8-standalone: $(STANDALONE_ARM64V8_ARCHIVE)

$(STANDALONE_ARM64V8_ARCHIVE): $(IMAGE_ARM64V8_DOCKERFILE)
	mkdir -p '$(DISTDIR)'
	'$(DOCKER)' run --rm \
		--env DEFAULT_ADMIN_PASSWORD='password' \
		'$(IMAGE_NAME):$(IMAGE_VERSION)-arm64v8' \
		/usr/share/biserver/bin/export.sh > '$(STANDALONE_ARM64V8_ARCHIVE)'

##################################################
## "load-*" targets
##################################################

define load_image
	zstd -dc '$(1)' | '$(DOCKER)' load
endef

define tag_image
	'$(DOCKER)' tag '$(1)' '$(2)'
endef

.PHONY: load-native-image
load-native-image:
	$(call load_image,$(IMAGE_NATIVE_TARBALL))
	$(call tag_image,$(IMAGE_NAME):$(IMAGE_VERSION),$(IMAGE_NAME):$(IMAGE_VERSION_MINOR))

.PHONY: load-cross-images
load-cross-images: load-amd64-image load-arm64v8-image

.PHONY: load-amd64-image
load-amd64-image:
	$(call load_image,$(IMAGE_AMD64_TARBALL))
	$(call tag_image,$(IMAGE_NAME):$(IMAGE_VERSION)-amd64,$(IMAGE_NAME):$(IMAGE_VERSION_MINOR)-amd64)

.PHONY: load-arm64v8-image
load-arm64v8-image:
	$(call load_image,$(IMAGE_ARM64V8_TARBALL))
	$(call tag_image,$(IMAGE_NAME):$(IMAGE_VERSION)-arm64v8,$(IMAGE_NAME):$(IMAGE_VERSION_MINOR)-arm64v8)

##################################################
## "push-*" targets
##################################################

define push_image
	'$(DOCKER)' push '$(1)'
endef

define push_cross_manifest
	'$(DOCKER)' manifest create --amend '$(1)' '$(2)-amd64' '$(2)-arm64v8'
	'$(DOCKER)' manifest annotate '$(1)' '$(2)-amd64' --os linux --arch amd64
	'$(DOCKER)' manifest annotate '$(1)' '$(2)-arm64v8' --os linux --arch arm64 --variant v8
	'$(DOCKER)' manifest push --purge '$(1)'
endef

.PHONY: push-native-image
push-native-image:
	@printf '%s\n' 'Unimplemented'

.PHONY: push-cross-images
push-cross-images: push-amd64-image push-arm64v8-image

.PHONY: push-amd64-image
push-amd64-image:
	$(call push_image,$(IMAGE_NAME):$(IMAGE_VERSION)-amd64)
	$(call push_image,$(IMAGE_NAME):$(IMAGE_VERSION_MINOR)-amd64)

.PHONY: push-arm64v8-image
push-arm64v8-image:
	$(call push_image,$(IMAGE_NAME):$(IMAGE_VERSION)-arm64v8)
	$(call push_image,$(IMAGE_NAME):$(IMAGE_VERSION_MINOR)-arm64v8)

push-cross-manifest:
	$(call push_cross_manifest,$(IMAGE_NAME):$(IMAGE_VERSION),$(IMAGE_NAME):$(IMAGE_VERSION))
	$(call push_cross_manifest,$(IMAGE_NAME):$(IMAGE_VERSION_MINOR),$(IMAGE_NAME):$(IMAGE_VERSION_MINOR))

##################################################
## "binfmt-*" targets
##################################################

.PHONY: binfmt-register
binfmt-register:
	'$(DOCKER)' run --rm --privileged docker.io/hectorm/qemu-user-static:latest --reset --persistent yes --credential yes

##################################################
## "clean" target
##################################################

.PHONY: clean
clean:
	rm -f '$(IMAGE_NATIVE_DOCKERFILE)' '$(IMAGE_AMD64_DOCKERFILE)' '$(IMAGE_ARM64V8_DOCKERFILE)'
	rm -f '$(IMAGE_NATIVE_TARBALL)' '$(IMAGE_AMD64_TARBALL)' '$(IMAGE_ARM64V8_TARBALL)'
	rm -f '$(STANDALONE_ARCHIVE)' '$(STANDALONE_AMD64_ARCHIVE)' '$(STANDALONE_ARM64V8_ARCHIVE)'
	if [ -d '$(DISTDIR)' ] && [ -z "$$(ls -A '$(DISTDIR)')" ]; then rmdir '$(DISTDIR)'; fi
