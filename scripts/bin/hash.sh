#!/bin/sh

set -eu
export LC_ALL=C

salt() { uuidgen | tr -d '-'; }
checksum() { sha256sum | head -c64; }
hex2bin() { xxd -r -p; }

PASSWORD=${1:?}
ITERATIONS=${2:-1000}
SALT=${3:-$(salt)}

HASH=$(printf -- '%s' "${SALT:?}${PASSWORD:?}" | checksum)
i=1; while [ "${i:?}" -lt "${ITERATIONS:?}" ]; do i=$((i+1))
	HASH=$(printf -- '%s' "${HASH:?}" | hex2bin | checksum);
done

printf -- '{SHA-256}%s-%s-%s' "${SALT:?}" "${ITERATIONS:?}" "${HASH:?}"
