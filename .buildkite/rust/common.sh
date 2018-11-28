#######################################
# Common initialization for Rust builds
#######################################

source .buildkite/scripts/common.sh

####################
# Set up environment
####################
export SGX_MODE="SIM"
export INTEL_SGX_SDK="/opt/sgxsdk"
export EKIDEN_UNSAFE_SKIP_AVR_VERIFY="1"
export RUST_BACKTRACE="1"

####################################################
# By default, .bashrc will quit if the shell
# is not interactive. It checks whether $PS1 is
# set to determine whether the shell is interactive.
# Here, we set PS1 to any random value so that we
# can source .bashrc and have it configure $PATH
# for things like node version manager (nvm) and
# sgxsdk.
####################################################
# TODO this is very unintuitive. Think of a better way to do this.
export PS1="set PS1 to anything so that we can source .bashrc"

# While sourcing .bashrc, temporarily ignore
# unset vars and do not print commands because
# it is a bunch of useless noise.
set +ux
. ~/.bashrc
set -ux

########################################
# Add SSH identity so that `cargo build`
# can successfully download dependencies
# from private github repos.
########################################
eval `ssh-agent -s`
trap_add "kill ${SSH_AGENT_PID}" EXIT

ssh-add || true
