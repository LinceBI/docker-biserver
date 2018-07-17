#!/usr/bin/make -f

MKFILE_RELPATH := $(shell printf -- '%s' '$(MAKEFILE_LIST)' | sed 's|^\ ||')
MKFILE_ABSPATH := $(shell readlink -f -- '$(MKFILE_RELPATH)')
MKFILE_DIR := $(shell dirname -- '$(MKFILE_ABSPATH)')

BISERVER_VERSION := 7.1.0.0-12
BISERVER_MAVEN_REPO := https://repo.stratebi.com/repository/pentaho-mvn/

DIST_DIR := $(MKFILE_DIR)/dist

DOCKER_IMAGE_NAMESPACE := stratebi
DOCKER_IMAGE_NAME := pentaho-biserver
DOCKER_IMAGE := $(DOCKER_IMAGE_NAMESPACE)/$(DOCKER_IMAGE_NAME)
DOCKER_IMAGE_TARBALL := $(DIST_DIR)/$(DOCKER_IMAGE_NAME).tgz
DOCKER_CONTAINER := $(DOCKER_IMAGE_NAME)
DOCKERFILE := $(MKFILE_DIR)/Dockerfile

.PHONY: all \
	build build-image save-image \
	clean clean-image clean-container clean-dist

all: build

build: save-image

build-image:
	docker build \
		--tag '$(DOCKER_IMAGE):latest' \
		--tag '$(DOCKER_IMAGE):$(BISERVER_VERSION)' \
		--build-arg BISERVER_VERSION='$(BISERVER_VERSION)' \
		--build-arg BISERVER_MAVEN_REPO='$(BISERVER_MAVEN_REPO)' \
		--file '$(DOCKERFILE)' \
		-- '$(MKFILE_DIR)'

save-image: build-image
	mkdir -p -- '$(DIST_DIR)'
	docker save -- '$(DOCKER_IMAGE)' | gzip > '$(DOCKER_IMAGE_TARBALL)'

clean: clean-image clean-dist

clean-image: clean-container
	-docker rmi -- '$(DOCKER_IMAGE)'

clean-container:
	-docker stop -- '$(DOCKER_CONTAINER)'
	-docker rm -- '$(DOCKER_CONTAINER)'

clean-dist:
	rm -f -- '$(DOCKER_IMAGE_TARBALL)'
	-rmdir -- '$(DIST_DIR)'
