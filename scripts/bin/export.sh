#!/bin/sh

set -eu
export LC_ALL=C

# Execute setup scripts
export EXPORT_ENABLED='true'
/usr/share/biserver/bin/setup.sh 1>&2

# Print tarball to stdout
GZIP=-4n tar \
	--checkpoint=10000 --checkpoint-action=echo='%{}T' --totals \
	--preserve-permissions --acls --selinux --xattrs --numeric-owner --sort=name \
	--format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,atime:=0,ctime:=0 \
	--exclude '*.erb' --exclude '.placeholder' \
	--create --gzip --file=- --directory "${BISERVER_HOME:?}" ./
