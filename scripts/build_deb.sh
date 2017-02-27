#!/bin/sh
# Copyright 2017 Roger Shimizu <rogershimizu@gmail.com>
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

if [ -d .git ]; then
	echo Please run this script in a clean place.
	echo e.g.
	echo "    mkdir -p ~/build-area/"
	echo "    cp $0 ~/build-area/"
	echo "    cd ~/build-area"
	echo "    ./$(basename $0)"
	exit
fi

apt_init() {
	DEPS="$1"
	DEPS_BPO="$2"
	if [ -n "$DEPS_BPO" ]; then
		BPO=${OSVER}-backports
		case "$OSID" in
		debian)
			REPO=http://httpredir.debian.org/debian
			;;
		ubuntu)
			REPO=http://archive.ubuntu.com/ubuntu
			;;
		esac
		sudo sh -c "printf \"deb $REPO ${OSVER}-backports main\" > /etc/apt/sources.list.d/${OSVER}-backports.list"
		sudo apt-get update
		sudo apt-get install -y -t $BPO $DEPS_BPO
	else
		sudo apt-get update
	fi
	sudo apt-get install -y $DEPS
}

# Cleanup
apt_clean() {
	sudo apt-get purge -y $DEPS $DEPS_BPO debhelper \
		libbloom-dev libcork-dev libcorkipset-dev libmbedtls-dev \
		libsodium-dev libbloom-build-deps simple-obfs-build-deps \
		shadowsocks-libev-build-deps
	sudo apt-get purge -y libcork-build-deps libcorkipset-build-deps
	sudo apt-get purge -y libsodium-build-deps
	sudo apt-get purge -y mbedtls-build-deps
	sudo apt-get autoremove -y
}

gbp_build() {
	REPO=$1
	BRANCH=$2
	PROJECT_NAME=$(basename $1|sed s/\.git$//)
	gbp clone --pristine-tar $REPO
	cd $PROJECT_NAME
	git checkout $BRANCH
	mk-build-deps --root-cmd sudo --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
	rm ${PROJECT_NAME}-build-deps_*.deb
	gbp buildpackage -us -uc --git-ignore-branch --git-pristine-tar
	git clean -fdx
	git reset --hard HEAD
	cd -
}

git_build() {
	REPO=$1
	BRANCH=$2
	PROJECT_NAME=$(basename $1|sed s/\.git$//)
	git clone $REPO
	cd $PROJECT_NAME
	git checkout $BRANCH
	mk-build-deps --root-cmd sudo --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
	rm ${PROJECT_NAME}-build-deps_*.deb
	gbp buildpackage -us -uc --git-ignore-branch
	git clean -fdx
	git reset --hard HEAD
	cd -
}

dsc_build() {
	DSC=$1
	DSC_FILE=$(basename $1)
	dget -ux $DSC
	PROJECT_NAME=$(grep ^Source: $DSC_FILE|cut -d" " -f2)
	echo cd ${PROJECT_NAME}-*
	cd ${PROJECT_NAME}-*
	mk-build-deps --root-cmd sudo --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
	rm ${PROJECT_NAME}-build-deps_*.deb
	dpkg-buildpackage -us -uc
	cd -
}

# Build and install libcork deb
build_install_libcork() {
	BRANCH=$1
	gbp_build https://github.com/rogers0/libcork $BRANCH
	sudo dpkg -i libcork-dev_*.deb libcork16_*.deb
}

# Build and install libcorkipset deb
build_install_libcorkipset() {
	BRANCH=$1
	gbp_build https://github.com/rogers0/libcorkipset $BRANCH
	sudo dpkg -i libcorkipset-dev_*.deb libcorkipset1_*.deb
}

# Build libmbedtls deb
build_install_libmbedtls() {
	BRANCH=$1
	gbp_build https://anonscm.debian.org/git/collab-maint/mbedtls.git $BRANCH
	sudo dpkg -i libmbed*.deb
}

# Build libsodium deb
build_install_libsodium() {
	dsc_build http://httpredir.debian.org/debian/pool/main/libs/libsodium/libsodium_1.0.11-1~bpo8+1.dsc
	sudo dpkg -i libsodium*.deb
}

# Build libbloom deb
build_install_libbloom() {
	BRANCH=$1
	gbp_build https://github.com/rogers0/libbloom $BRANCH
	sudo dpkg -i libbloom-dev_*.deb libbloom1_*.deb
}

# Add patch to work on system with debhelper 9 only
patch_sslibev_dh9() {
	BRANCH=$1
	gbp clone --pristine-tar https://anonscm.debian.org/git/collab-maint/shadowsocks-libev.git
	cd shadowsocks-libev
	git checkout $BRANCH
	sed -i 's/dh $@/dh $@ --with systemd,autoreconf/' debian/rules
	sed -i 's/debhelper (>= 10)/debhelper (>= 9), dh-systemd, dh-autoreconf/' debian/control
	echo 9 > debian/compat
	git add -u
	git commit -m "Patch to work with ubuntu trusty (14.04)"
	cd -
}

# Build and install shadowsocks-libev deb
build_install_sslibev() {
	BRANCH=$1
	gbp_build https://anonscm.debian.org/git/collab-maint/shadowsocks-libev.git $BRANCH
	sudo dpkg -i shadowsocks-libev_*.deb
	sudo apt-get install -fy
}

# Build and install simple-obfs
build_install_simpleobfs() {
	BRANCH=$1
	git_build https://github.com/rogers0/simple-obfs $BRANCH
	sudo dpkg -i simple-obfs_*.deb
	sudo apt-get install -fy
}

export XZ_DEFAULTS=--memlimit=128MiB

OSID=$(grep ^ID= /etc/os-release|cut -d= -f2)
OSVER=$(lsb_release -cs)

case "$OSVER" in
wheezy|precise)
	echo Sorry, your system $OSID/$OSVER is not supported.
	;;
jessie)
	apt_init "git-buildpackage equivs" "debhelper libsodium-dev"
	build_install_libbloom exp1
	build_install_sslibev exp1
	build_install_simpleobfs exp1
	apt_clean
	;;
stretch|unstable|sid)
	apt_init "git-buildpackage equivs"
	build_install_libbloom exp1
	build_install_sslibev exp1
	build_install_simpleobfs exp1
	apt_clean
	;;
trusty)
	apt_init "git-buildpackage equivs"
	build_install_libcork trusty
	build_install_libcorkipset trusty
	build_install_libmbedtls debian/jessie-backports
	build_install_libsodium
	build_install_libbloom exp1_trusty
	patch_sslibev_dh9 exp1
	build_install_sslibev exp1
	build_install_simpleobfs exp1_trusty
	apt_clean
	;;
xenial)
	apt_init "git-buildpackage equivs" debhelper
	build_install_libcork debian
	build_install_libcorkipset debian
	build_install_libbloom exp1
	build_install_sslibev exp1
	build_install_simpleobfs exp1
	apt_clean
	;;
yakkety)
	apt_init "git-buildpackage equivs"
	build_install_libcork debian
	build_install_libcorkipset debian
	build_install_libbloom exp1
	build_install_sslibev exp1
	build_install_simpleobfs exp1
	apt_clean
	;;
*)
	echo Your system $OSID/$OSVER is not supported yet.
	echo Please report issue:
	echo "    https://github.com/shadowsocks/shadowsocks-libev/issues/new"
	;;
esac
