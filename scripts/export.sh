#!/bin/sh

set -eu
export LC_ALL=C

export EXPORT_ENABLED='true'

# Execute setup scripts
/opt/scripts/setup.sh >/dev/null

# Print tarball to stdout
GZIP=-4n tar \
	--totals \
	--checkpoint=10000 \
	--checkpoint-action=echo='%{}T' \
	--format=posix \
	--preserve-permissions \
	--xattrs --acls --selinux \
	--create --gzip --file=- \
	--exclude '*.erb' \
	--exclude '.placeholder' \
	--directory "${BISERVER_HOME}" .
