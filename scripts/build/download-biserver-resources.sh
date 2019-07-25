#!/bin/sh

set -eu
export LC_ALL=C

VERSION="${1:?}"
TARGET_DIR="${2:?}"
BASE_URL='https://raw.githubusercontent.com/pentaho/pentaho-platform'

# Use only major and minor version number
VERSION="$(printf -- '%s' "${VERSION}" | sed 's|^\([0-9]\.[0-9]\).*$|\1|')"

# Download resources
mkdir -p "${TARGET_DIR}"
(cd "${TARGET_DIR}" \
	&& curl -LO "${BASE_URL}"/"${VERSION}"/'assemblies/pentaho-server/src/main/resources/biserver/import-export.{bat,sh}' \
	&& curl -LO "${BASE_URL}"/"${VERSION}"/'assemblies/pentaho-server/src/main/resources/biserver/set-pentaho-env.{bat,sh}' \
	&& curl -LO "${BASE_URL}"/"${VERSION}"/'assemblies/pentaho-server/src/main/resources/biserver/start-pentaho.{bat,sh}' \
	&& curl -LO "${BASE_URL}"/"${VERSION}"/'assemblies/pentaho-server/src/main/resources/biserver/stop-pentaho.{bat,sh}' \
)
