#!/bin/sh
set -e
set -x
docker build -t althttpd_static \
       --build-arg cachebust=$(date +%s) \
       "$@" \
       -f Dockerfile.althttpd \
       .
docker create --name althttpd althttpd_static
docker cp althttpd:/althttpd-src/althttpd althttpd
docker cp althttpd:/althttpd-src/althttpsd althttpsd
strip althttpd althttpsd
ls -la althttp*
docker container rm althttpd
set +x

cat <<EOF
Now maybe do:

  docker image rm \$(docker image ls | grep -e althttpd_static -e alpine | awk '{print \$3}')
or:
  docker system prune --force
EOF
