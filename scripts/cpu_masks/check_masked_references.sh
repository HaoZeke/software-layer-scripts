#!/bin/bash
#
# Check that a build host presents each CPU target exactly under its cpuidmask
# profile: run scripts/native_flags/check_native_flags.sh for the target with
# libcpuidmask.so preloaded, so the compilers resolve the native flag as they
# would on the target.
#
# A mask can only hide CPUID bits. A target needs a host whose CPU has every
# feature the target's reference enables, with CPUID faulting in the kernel
# (Intel since Linux 4.12; AMD since 6.17). Hosts without CPUID faulting are
# skipped with a message.
#
# usage: check_masked_references.sh [--below-host | SUBDIR...]   (default: every profile)
#
#   --below-host   check the targets that eessi_archdetect.sh lists as compatible with this host,
#                  below its own target (which check_native_flags.sh covers unmasked)
#
# Environment variables:
#   EESSI_VERSION_TO_CHECK - EESSI version whose compilers are checked (default 2025.06)

set -uo pipefail

SCRIPT_DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))
TOPDIR=$(realpath ${SCRIPT_DIR}/../..)
eessi_version=${EESSI_VERSION_TO_CHECK:-2025.06}

workdir=$(mktemp -d)
trap 'rm -rf ${workdir}' EXIT
cc -O2 -Wall -shared -fPIC -o ${workdir}/libcpuidmask.so ${SCRIPT_DIR}/cpuidmask.c -ldl || exit 1

# CPUIDMASK_STRICT makes a preloaded process exit with 97 without CPUID faulting
CPUIDMASK_STRICT=1 LD_PRELOAD=${workdir}/libcpuidmask.so CPUIDMASK_RULES=/dev/null true
if [[ $? -eq 97 ]]; then
    echo ">> This host has no CPUID faulting, skipping the masked reference check"
    exit 0
fi

if [[ "${1:-}" == "--below-host" ]]; then
    compatible=$(${TOPDIR}/init/eessi_archdetect.sh -a cpupath) || exit 1
    subdirs=()
    for subdir in $(echo ${compatible} | tr ':' '\n' | tail -n +2 | grep -v '/generic$'); do
        [[ -f ${SCRIPT_DIR}/profiles/${subdir}.rules ]] && subdirs+=(${subdir})
    done
    if [[ ${#subdirs[@]} -eq 0 ]]; then
        echo ">> No profile for a target below this host (${compatible}), nothing to check"
        exit 0
    fi
elif [[ $# -gt 0 ]]; then
    subdirs=("$@")
else
    subdirs=($(cd ${SCRIPT_DIR}/profiles && find . -name '*.rules' | sed 's|^\./||; s|\.rules$||' | sort))
fi

failed=()
for subdir in "${subdirs[@]}"; do
    profile=${SCRIPT_DIR}/profiles/${subdir}.rules
    if [[ ! -f "${profile}" ]]; then
        echo "ERROR: no cpuidmask profile for ${subdir} (${profile})"
        failed+=(${subdir})
        continue
    fi
    echo ">> Checking ${subdir} under ${profile}"
    (
        set +uo pipefail
        export EESSI_SOFTWARE_SUBDIR_OVERRIDE=${subdir}
        source /cvmfs/software.eessi.io/versions/${eessi_version}/init/lmod/bash > /dev/null 2>&1
        if [[ "${EESSI_SOFTWARE_SUBDIR:-}" != "${subdir}" ]]; then
            echo "ERROR: failed to initialise EESSI ${eessi_version} for ${subdir}"
            exit 1
        fi
        export CPUIDMASK_RULES=${profile} CPUIDMASK_STRICT=1
        export LD_PRELOAD=${workdir}/libcpuidmask.so${LD_PRELOAD:+:${LD_PRELOAD}}
        ${TOPDIR}/scripts/native_flags/check_native_flags.sh
    ) > ${workdir}/check.log 2>&1
    rc=$?
    cat ${workdir}/check.log
    if [[ ${rc} -ne 0 ]]; then
        failed+=(${subdir})
        # A flag the reference enables but the masked host disables is one the host lacks
        if grep -E '^ +< (-m|-target-feature \+)' ${workdir}/check.log | grep -qv -- '< -mno-'; then
            echo ">> Flags enabled in the reference but disabled here are features this host's CPU does not have;"
            echo "   a mask can only hide features, so this host cannot present ${subdir}."
        fi
    fi
done

if [[ ${#failed[@]} -gt 0 ]]; then
    echo "ERROR: the masked native flags do not match the reference for: ${failed[*]}"
    exit 1
fi
echo ">> The masked native flags match the references for: ${subdirs[*]}"
