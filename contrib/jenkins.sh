#!/usr/bin/env bash
# jenkins build helper script for libosmo-pfcp.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
#

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
export PATH="$inst/bin:$PATH"

osmo-build-dep.sh libosmocore "" --disable-doxygen

# Additional configure options and depends
CONFIG=""
if [ "$WITH_MANUALS" = "1" ]; then
	CONFIG="--enable-manuals"
fi

set +x
echo
echo
echo
echo " =============================== libosmo-pfcp ==============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure --enable-sanitize --enable-werror $CONFIG
$MAKE $PARALLEL_MAKE
LD_LIBRARY_PATH="$inst/lib" $MAKE check \
  || cat-testlogs.sh
LD_LIBRARY_PATH="$inst/lib" \
  DISTCHECK_CONFIGURE_FLAGS="$CONFIG" \
  $MAKE $PARALLEL_MAKE distcheck \
  || cat-testlogs.sh

$MAKE $PARALLEL_MAKE maintainer-clean
osmo-clean-workspace.sh
