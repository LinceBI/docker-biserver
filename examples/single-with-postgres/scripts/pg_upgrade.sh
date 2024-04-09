#!/bin/sh

set -eu
export LC_ALL=C

DOCKER=$(command -v docker 2>/dev/null)

PGVER_OLD=${1:?}
PGVER_NEW=${2:?}
DATA_VOLUME=${3:?}
TEMP_VOLUME=${DATA_VOLUME:?}-$(tr -dc 'a-z0-9' < /dev/urandom | head -c12)

: "PGUSER=${PGUSER:=postgres}"

cleanup() { "${DOCKER:?}" volume rm -f "${TEMP_VOLUME:?}" > /dev/null; }
trap cleanup EXIT

"${DOCKER:?}" run --rm \
	--env PGUSER="${PGUSER:?}" --env POSTGRES_INITDB_ARGS=--username="${PGUSER:?}" \
	--mount type=volume,src="${DATA_VOLUME:?}",dst=/var/lib/postgresql/"${PGVER_OLD:?}"/data/ \
	--mount type=volume,src="${TEMP_VOLUME:?}",dst=/var/lib/postgresql/"${PGVER_NEW:?}"/data/ \
	docker.io/tianon/postgres-upgrade:"${PGVER_OLD:?}"-to-"${PGVER_NEW:?}"

"${DOCKER:?}" run --rm \
	--entrypoint /bin/sh \
	--mount type=volume,src="${DATA_VOLUME:?}",dst=/pg/data/ \
	--mount type=volume,src="${TEMP_VOLUME:?}",dst=/pg/temp/ \
	docker.io/alpine:latest \
	-euc "$(cat <<-'EOF'
		apk add rsync
		rsync -aAXv --remove-source-files --delete-before --exclude=pg_hba.conf /pg/temp/ /pg/data/
	EOF
	)"
