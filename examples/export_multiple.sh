#!/bin/sh

set -eu
export LC_ALL=C

DOCKER_BISERVER_IMAGE=stratebi/pentaho-biserver:8.1.0.0-365
SETUP_JSON="$(cat <<-EOF
  {
    "root": "helium",
    "servers": [
      {
        "name": "helium",
        "enabled": true,
        "env": {}
      },
      {
        "name": "neon",
        "enabled": true,
        "env": {}
      },
      {
        "name": "argon",
        "enabled": true,
        "env": {}
      }
    ]
  }
EOF
)"

docker run --rm \
	--env SETUP_JSON="${SETUP_JSON}" \
	"${DOCKER_BISERVER_IMAGE}" /opt/scripts/export.sh
