#!/bin/sh

set -eu
export LC_ALL=C

export EXPORT_ENABLED='true'

# Execute setup scripts
/opt/scripts/setup.sh >/dev/null

# Print tarball to stdout
GZIP=-4n tar \
	--checkpoint=10000 --checkpoint-action=echo='%{}T' --totals \
	--preserve-permissions --acls --selinux --xattrs --numeric-owner --sort=name \
	--format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,atime:=0,ctime:=0 \
	--exclude '*.erb' --exclude '.placeholder' \
	--create --gzip --file=- --directory "${BISERVER_HOME}" .
