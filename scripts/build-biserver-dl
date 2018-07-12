#!/bin/sh

set -eu
export LC_ALL=C

VERSION="${1:?}"
MAVEN_REPO="${2:?}"
TARGET_DIR="${3:?}"

downloadArtifact() {
	curl -L -- "$1" > "$2"
	printf -- '%s %s' "$(curl -fsSL "$1".sha1)" "$2" | sha1sum -c
}

mkdir -p "${TARGET_DIR}"
downloadArtifact "${MAVEN_REPO}/pentaho/pentaho-solutions/${VERSION}/pentaho-solutions-${VERSION}.zip" "${TARGET_DIR}/pentaho-solutions.zip"
downloadArtifact "${MAVEN_REPO}/pentaho/pentaho-data/${VERSION}/pentaho-data-${VERSION}.zip" "${TARGET_DIR}/pentaho-data.zip"
downloadArtifact "${MAVEN_REPO}/pentaho/pentaho-war/${VERSION}/pentaho-war-${VERSION}.war" "${TARGET_DIR}/pentaho.war"
downloadArtifact "${MAVEN_REPO}/pentaho/pentaho-style/${VERSION}/pentaho-style-${VERSION}.war" "${TARGET_DIR}/pentaho-style.war"
