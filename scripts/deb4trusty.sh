#!/bin/sh
# Copyright 2017 Roger Shimizu <rogershimizu@gmail.com>
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

DEPS="git-buildpackage equivs dh-autoreconf dh-systemd"
sudo apt-get install -y $DEPS

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

# Build libcork deb if you don't have
gbp_build https://github.com/rogers0/libcork trusty
sudo dpkg -i libcork-dev_*.deb libcork16_*.deb

# Build libcorkipset deb if you don't have
gbp_build https://github.com/rogers0/libcorkipset trusty
sudo dpkg -i libcorkipset-dev_*.deb libcorkipset1_*.deb

# Build libmbedtls deb if you don't have
gbp_build https://anonscm.debian.org/cgit/collab-maint/mbedtls.git debian/jessie-backports
sudo dpkg -i libmbed*.deb

# Build libsodium deb if you don't have
dsc_build http://httpredir.debian.org/debian/pool/main/libs/libsodium/libsodium_1.0.11-1~bpo8+1.dsc
sudo dpkg -i libsodium*.deb

# Build shadowsocks-libev
gbp clone --pristine-tar https://anonscm.debian.org/git/collab-maint/shadowsocks-libev.git
# Add patch to work with ubuntu trusty (14.04)
cd shadowsocks-libev
sed -i s/--with\ systemd/--with\ systemd\ --with\ autoreconf/ debian/rules
sed -i s/debhelper\ \(\>=\ 10\)/debhelper\ \(\>=\ 9\)/ debian/control
git add -u
git commit -m "Patch to work with ubuntu trusty (14.04)"
cd -
gbp_build https://anonscm.debian.org/git/collab-maint/shadowsocks-libev.git master
sudo dpkg -i shadowsocks-libev_*.deb
sudo apt-get install -fy

# Cleanup
sudo apt-get purge -y libcork-build-deps libcorkipset-build-deps shadowsocks-libev-build-deps \
	$DEPS $DEPS_BPO libcork-dev libcorkipset-dev
sudo apt-get autoremove -y
