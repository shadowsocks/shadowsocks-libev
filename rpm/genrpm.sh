#!/usr/bin/env bash
set -e

g_script_path=$(dirname $(readlink -e $0))
g_toplevel_path=$(pushd $g_script_path > /dev/null 2>&1; \
                  git rev-parse --show-toplevel; \
                  popd > /dev/null 2>&1)

g_version=$(git tag -l v* | sort --version-sort | tail -1)
g_version=${g_version#"v"}
g_format="tar.gz"
g_name="shadowsocks-libev"

g_rpmbuild_topdir="${g_toplevel_path}/rpm"
g_rpmbuild_conditions=

show_help()
{
    echo -e "`basename $0`  [option] [argument]"
    echo
    echo -e "Options:"
    echo -e "  -h    show this help."
    echo -e "  -v    with argument version (${g_version} by default)."
    echo -e "  -f    with argument format (tar.gz by default) used by git archive."
    echo
    echo -e "Examples:"
    echo -e "  to build base on version \`2.4.1' with format \`tar.xz', run:"
    echo -e "    `basename $0` -f tar.xz -v 2.4.1"
}

version_greater_equal()
{
    [ "$1" = $(printf "$1\n$2\n" | sort --version-sort | tail -1) ]
}

verify_options()
{
    local completion_min_verion="2.6.0"
    local archive_format_supported_max_version="2.6.2"

    version_greater_equal ${g_version} ${completion_min_verion} \
        && g_rpmbuild_conditions="${g_rpmbuild_conditions} --with completion" || :

    if ! version_greater_equal ${archive_format_supported_max_version} ${g_version}; then
        g_rpmbuild_conditions="${g_rpmbuild_conditions} --with autogen"

        if [ "${g_format}" != "tar" ]; then
            echo -e "version(${g_version}) greater than ${archive_format_supported_max_version} can only use archive format \`tar'."
            echo -e "change format from \`${g_format}' to \`tar'"
            g_format="tar"
        fi
    fi
}

generate_tarball()
{
    local tarball_name="${g_name}-${g_version}"
    local tarball_dir="${g_rpmbuild_topdir}/SOURCES"

    pushd ${g_toplevel_path}

    git archive "v${g_version}" \
        --format="${g_format}" \
        --prefix="${tarball_name}/" \
        -o "${tarball_dir}/${tarball_name}.${g_format}"

    git ls-tree -dr "v${g_version}" | grep commit \
        | while read eat_mod eat_type mod_sha mod_path; do \
        [ "${mod_path}" = "" ] && continue || :; \
        (pushd ${mod_path=} \
                && git archive ${mod_sha} \
                       --prefix="${tarball_name}/${mod_path}/" \
                       -o "${tarball_dir}/sub_mod.tar" \
                && tar --concatenate "${tarball_dir}/sub_mod.tar" \
                       --file="${tarball_dir}/${tarball_name}.tar" \
                && rm "${tarball_dir}/sub_mod.tar" \
                && popd) \
            done

    popd
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
                g_version=${OPTARG#"v"}
            else
                g_version=${OPTARG}
            fi
            ;;
        f)
            g_format=${OPTARG}
            ;;
        *)
            exit 1
            ;;
    esac
done

verify_options

generate_tarball

spec_path="${g_rpmbuild_topdir}/SPECS/shadowsocks-libev.spec"
sed -e "s/^\(Version:	\).*$/\1${g_version}/" \
    -e "s/^\(Source0:	\).*$/\1${g_name}-${g_version}.${g_format}/" \
    "${spec_path}".in > "${spec_path}"

rpmbuild -bb ${spec_path} \
         --define "%_topdir ${g_rpmbuild_topdir}" \
         ${g_rpmbuild_conditions} \
