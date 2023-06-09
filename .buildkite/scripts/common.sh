##################
# Common functions
##################

# Temporary artifacts download directory.
ARTIFACTS_CACHE_DIR=/tmp/artifacts
ARTIFACTS_TMP_DIR=/tmp/artifacts_tmp
CLEANING_UP=0

# Download an artifact and change its mode
download_artifact() {
    local name=$1
    local dst_dir=$2
    local mode=${3:-644}

    mkdir -p ${ARTIFACTS_CACHE_DIR} ${ARTIFACTS_TMP_DIR} ${dst_dir}

    if [ -f "${ARTIFACTS_CACHE_DIR}/${name}" ] && (echo "$(buildkite-agent artifact shasum ${name})  ${ARTIFACTS_CACHE_DIR}/${name}" | sha1sum -c); then
        # use artifact from cache
        cp -f ${ARTIFACTS_CACHE_DIR}/${name} ${dst_dir}/${name}
    else
        # download artifact and cache it
        buildkite-agent artifact download ${name} ${ARTIFACTS_TMP_DIR}/
        cp -f ${ARTIFACTS_TMP_DIR}/${name} ${dst_dir}/${name}
        mv -f ${ARTIFACTS_TMP_DIR}/${name} ${ARTIFACTS_CACHE_DIR}/${name}
    fi
    chmod ${mode} ${dst_dir}/${name}
}

cleanup() {
    if [ "${CLEANING_UP}" == "1" ]; then
        return
    fi
    CLEANING_UP=1

    # Send all child processes a kill signal.
    pkill -P $BASHPID || true

    # Wait for all child processes to exit.
    # Helpful context:
    # https://stackoverflow.com/questions/17894720/kill-a-process-and-wait-for-the-process-to-exit
    wait || true

    CLEANING_UP=0
}

# appends a command to a trap
#
# - 1st arg:  code to add
# - remaining args:  names of traps to modify
#
trap_add() {
    trap_add_cmd=$1; shift || fatal "${FUNCNAME} usage error"
    for trap_add_name in "$@"; do
        trap -- "$(
            # helper fn to get existing trap command from output
            # of trap -p
            extract_trap_cmd() { printf '%s\n' "${3:-}"; }
            # print existing trap command with newline
            eval "extract_trap_cmd $(trap -p "${trap_add_name}")"
            # print the new trap command
            printf '%s\n' "${trap_add_cmd}"
        )" "${trap_add_name}" \
            || fatal "unable to add to trap ${trap_add_name}"
    done
}
# set the trace attribute for the above function.  this is
# required to modify DEBUG or RETURN traps because functions don't
# inherit them unless the trace attribute is set
declare -f -t trap_add

# Ensure cleanup on exit.
trap_add 'cleanup' EXIT
