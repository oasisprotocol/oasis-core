#######################################
# Common initialization for Rust builds
#######################################

source .buildkite/scripts/common.sh

####################
# Set up environment
####################
export EKIDEN_UNSAFE_SKIP_AVR_VERIFY="1"
export EKIDEN_UNSAFE_SKIP_KM_POLICY="1"
export RUST_BACKTRACE="1"

########################################
# Add SSH identity so that `cargo build`
# can successfully download dependencies
# from private github repos.
########################################
eval `ssh-agent -s`
cleanup_ssh_agent() {
    kill ${SSH_AGENT_PID} || true
}
trap_add "cleanup_ssh_agent" EXIT

ssh-add || true
