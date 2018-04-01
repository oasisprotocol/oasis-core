#!/bin/bash -e

if [ -z "$1" ]
  then
    echo "Usage: $0 [experiment name]"
    exit 1
fi
EXPERIMENT="$1"

# Set benchmark binaries to run.
# IMPORTANT: These binaries must exist in the ekiden/core image!
case $EXPERIMENT in
    "token")
        BENCHMARK_BINARIES="benchmark-token-get-balance benchmark-token-transfer"
         ;;
    "ethtoken")
        BENCHMARK_BINARIES="benchmark-ethtoken-get-balance benchmark-ethtoken-transfer"
        ;;
    "dp-credit-scoring")
        BENCHMARK_BINARIES="benchmark-dp-credit-scoring-infer benchmark-dp-credit-scoring-train"
        ;;
    "iot-learner")
        BENCHMARK_BINARIES="benchmark-iot-learner-infer benchmark-iot-learner-train"
        ;;
    *)
        echo "Unrecognized experiment name: ${EXPERIMENT}"
        exit 1
esac

# Number of threads to run. Note that valid values depend on configuration of the
# 'contract' container in token.yaml.
THREADS="8 16 32"
# Number of runs to execute per thread.
RUNS="1000"
# Target node.
TARGET="ekiden-benchmark-1"
# Node placement condition based on labels.
NODE_LABEL_KEY="experiments"
NODE_LABEL_VALUE="client"
# Results output file.
OUTPUT="${EXPERIMENT}.$(date --iso-8601=ns).txt"

# Helper logger function.
log() {
    echo $* | tee -a "results/${OUTPUT}"
}

# Helper function for running an Ekiden benchmark.
benchmark() {
    local script=$*

    kubectl run ekiden-${EXPERIMENT}-benchmark \
        --attach \
        --rm \
        --overrides='{"apiVersion": "v1", "spec": {"nodeSelector": {"'${NODE_LABEL_KEY}'": "'${NODE_LABEL_VALUE}'"}}}' \
        --command \
        --quiet \
        --image=ekiden/core:latest \
        --image-pull-policy=Always \
        --restart=Never \
        -- bash -c "${script}" | tee -a "results/${OUTPUT}"
}

# Check if any node is tagged.
if [ -z "$(kubectl get nodes -l "${NODE_LABEL_KEY} == ${NODE_LABEL_VALUE}" -o name)" ]; then
    echo "ERROR: No nodes are tagged to run the benchmark client."
    echo ""
    echo "Use the following command to tag a node first:"
    echo "  kubectl label nodes <node-name> ${NODE_LABEL_KEY}=${NODE_LABEL_VALUE}"
    echo ""
    echo "The following nodes are available:"
    kubectl get nodes
    echo ""
    echo "Current pod placements are as follows:"
    kubectl get pods -o wide
    echo ""
    exit 1
fi

echo "Results will be written to: results/${OUTPUT}"
mkdir -p results

log "Starting benchmarks at $(date --iso-8601=seconds)."

# Run benchmarks.
for benchmark in ${BENCHMARK_BINARIES}; do
    log "------------------------------ ${benchmark} ------------------------------"

    for threads in ${THREADS}; do
        log "Benchmarking with ${threads} thread(s)."
        sleep 5

        MRENCLAVE_CMD="\$(cat /ekiden/lib/${EXPERIMENT}.mrenclave)"

        benchmark \
            ${benchmark} \
                --benchmark-threads ${threads} \
                --benchmark-runs ${RUNS} \
                --host ${TARGET}.ekiden-benchmark.default.svc.cluster.local \
                --mr-enclave ${MRENCLAVE_CMD}

        log ""
    done
done

log "Benchmarks finished at $(date --iso-8601=seconds)."
