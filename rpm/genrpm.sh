#!/usr/bin/env bash
set -e

show_help()
{
    echo -e "`basename $0`  [option] [argument]"
    echo
    echo -e "Options:"
    echo -e "  -h    show this help."
    echo -e "  -v    with argument version (2.4.1 by default)."
    echo -e "  -f    with argument format (tar.xz by default) used by git archive."
    echo
    echo -e "Examples:"
    echo -e "  to build base on version \`2.4.1' with format \`tar.xz', run:"
    echo -e "    `basename $0` -f tar.xz -v 2.4.1"
}

while getopts "hv:f:" opt
do
    case ${opt} in
        h)
            show_help
            exit 0
            ;;
        v)
            if [ "${OPTARG}" = v* ]; then
                version=${OPTARG#"v"}
            else
                version=${OPTARG}
            fi
            ;;
        f)
            format=${OPTARG}
            ;;
        *)
            exit 1
            ;;
    esac
done

get_att_val()
{
    att=$1
    val=$2

    if [ -z $(eval echo \$$att) ]; then
        eval $att=$val
    fi
}

get_att_val version "2.4.1"
get_att_val format "tar.xz"

name="shadowsocks-libev"
spec_name="shadowsocks-libev.spec"

pushd `git rev-parse --show-toplevel`
git archive v${version} --format=${format} --prefix=${name}-${version}/ -o rpm/SOURCES/${name}-${version}.${format}
pushd rpm

sed -i -e "s/^\(Version:	\).*$/\1${version}/" \
       -e "s/^\(Source0:	\).*$/\1${name}-${version}.${format}/" \
    SPECS/${spec_name}

rpmbuild -bb SPECS/${spec_name} --define "%_topdir `pwd`"
