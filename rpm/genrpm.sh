#!/usr/bin/env bash
set -e


name="shadowsocks-libev"
spec_name="${name}.spec"
version=$(git tag -l v* | tail -1)
format="tar.xz"
repo_dir=$(pushd $(dirname $(readlink -e $0)) > /dev/null && git rev-parse --show-toplevel)


show_help()
{
    echo -e "Usage:"
    echo -e "  `basename $0`  [option] [argument]"
    echo
    echo -e "Options:"
    echo -e "  -h    show this help."
    echo -e "  -v    with argument version (\`${version}' by default)."
    echo -e "  -f    with argument format (\`${format}' by default) used by \`git archive'."
    echo
    echo -e "Description:"
    echo -e "  This will use \`git archive' to generate a spefical version of "
    echo -e "  \`${name}', which then will be used to build the final rpm packages."
    echo
    echo -e "Examples:"
    echo -e "  to build base on version \`${version}' with format \`${format}', run:"
    echo -e "    `basename $0` -f tar.xz -v ${version}"
}

while getopts "hv:f:" opt
do
    case ${opt} in
        h)
            show_help
            exit 0
            ;;
        v)
            version=${OPTARG}
            ;;
        f)
            format=${OPTARG}
            ;;
        *)
            echo "try \``basename $0` -h' for more details."
            exit 1
            ;;
    esac
done

version=${version#"v"}

pushd ${repo_dir}
git archive v${version} \
    --format=${format} --prefix=${name}-${version}/ \
    -o rpm/SOURCES/${name}-${version}.${format}
pushd rpm

sed -e "s/__FAKE_VERSION_TO_BE_SUBSTITUTED__/${version}/g" \
    -e "s/__FAKE_FORMAT_TO_BE_SUBSTITUTED__/${format}/g" \
    SPECS/${spec_name}.template > SPECS/${spec_name}

rpmbuild -bb SPECS/${spec_name} --define "%_topdir `pwd`"
