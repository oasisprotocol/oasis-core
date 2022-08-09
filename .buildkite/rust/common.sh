#######################################
# Common initialization for Rust builds
#######################################

source .buildkite/scripts/common.sh

####################
# Set up environment
####################
export OASIS_UNSAFE_SKIP_AVR_VERIFY="1"
export OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES="1"
export RUST_BACKTRACE="1"
