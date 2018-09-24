#
# Dockerfile for building MinGW port
#
# This file is part of the shadowsocks-libev.
#
# shadowsocks-libev is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# shadowsocks-libev is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with shadowsocks-libev; see the file COPYING. If not, see
# <http://www.gnu.org/licenses/>.
#

FROM debian:testing

ARG REPO=shadowsocks
ARG REV=master

ADD prepare.sh /

RUN \
  /bin/bash -c "source /prepare.sh && dk_prepare" && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /build

RUN /bin/bash -c "source /prepare.sh && dk_download"

ADD deps.sh /
RUN /bin/bash -c "source /deps.sh && dk_deps"

ADD build.sh /

ARG REBUILD=0
ARG PLUGIN=true

RUN /bin/bash -c "source /build.sh && dk_build && dk_package"
