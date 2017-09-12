#!/usr/bin/env bash
set -e

SELF=$(readlink -f -- "$0")
HERE=$(dirname -- "$SELF")

show_help()
{
    echo -e "`basename $0` [OPTION...]"
    echo
    echo -e "Options:"
    echo -e "  -h    show this help."
    echo -e "  -s    use system shared libraries"
}

OPT_USE_SYSTEM_LIB=0

while getopts "hs" opt
do
    case ${opt} in
        h)
            show_help
            exit 0
            ;;

		s)
            OPT_USE_SYSTEM_LIB=1
			;;
        *)
			show_help
            exit 1
            ;;
    esac
done

# determine version and release number
GIT_DESCRIBE=$(git describe --tags --match 'v*' --long)
# GIT_DESCRIBE is like v3.0.3-11-g1e3f35c-dirty

if [[ ! "$GIT_DESCRIBE" =~ ^v([^-]+)-([0-9]+)-g([0-9a-f]+)$ ]]; then
    >&2 echo 'ERROR - unrecognized `git describe` output: '"$GIT_DESCRIBE"
    exit 1
fi

TARGET_VERSION=${BASH_REMATCH[1]}
TARGET_COMMITS=${BASH_REMATCH[2]}
TARGET_SHA1=${BASH_REMATCH[3]}

TARGET_RELEASE=1
if [ "$TARGET_COMMITS" -gt 0 ]; then
    TARGET_RELEASE+=".$TARGET_COMMITS.git$TARGET_SHA1"
fi

TARGET_VERREL=$TARGET_VERSION-$TARGET_RELEASE
>&2 echo "INFO - RPM version-release is $TARGET_VERREL."

# archive tarball from Git workspace
export TARGET_TARBALL_NAME=shadowsocks-libev-$TARGET_VERSION
export TARGET_TARBALL_DIR=$HERE/SOURCES
mkdir -p -- "$TARGET_TARBALL_DIR"
pushd "$HERE"/..
# archive this repo
git archive HEAD --format=tar --prefix="$TARGET_TARBALL_NAME/" \
    -o "$TARGET_TARBALL_DIR/$TARGET_TARBALL_NAME.tar"
# archive submodules
git submodule update --init
git submodule foreach 'git archive HEAD --format=tar \
        --prefix="$TARGET_TARBALL_NAME/$path/" \
        -o "$TARGET_TARBALL_DIR/$TARGET_TARBALL_NAME-submodule-$path-$sha1.tar"
    tar -n --concatenate --file="$TARGET_TARBALL_DIR/$TARGET_TARBALL_NAME.tar" \
        "$TARGET_TARBALL_DIR/$TARGET_TARBALL_NAME-submodule-$path-$sha1.tar"'
gzip -c "$TARGET_TARBALL_DIR/$TARGET_TARBALL_NAME.tar" > "$TARGET_TARBALL_DIR/$TARGET_TARBALL_NAME.tar.gz"
popd

# generate spec file
TARGET_SPEC_DIR=$HERE/SPECS
mkdir -p -- "$TARGET_SPEC_DIR"
TARGET_SPEC_PATH=$TARGET_SPEC_DIR/shadowsocks-libev.spec
sed -e "s/^\(Version:\).*$/\1       ${TARGET_VERSION}/" \
    -e "s/^\(Release:\).*$/\1       ${TARGET_RELEASE}%{?dist}/" \
    -e "s/^\(Source0:\).*$/\1       ${TARGET_TARBALL_NAME}.tar.gz/" \
    "${TARGET_SPEC_PATH}".in > "${TARGET_SPEC_PATH}"

# build rpms
rpmbuild -ba "$TARGET_SPEC_PATH" \
         --define "%_topdir $HERE" \
         --define "%use_system_lib $OPT_USE_SYSTEM_LIB"
