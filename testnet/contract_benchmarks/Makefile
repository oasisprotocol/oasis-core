SHELL := /bin/bash

# List of experiments. If adding a new experiment, the name below must match the enclave binary name.
EXPERIMENTS := token ethtoken dp-credit-scoring iot-learner

create: check-valid-experiment
	@echo "Preparing '$(experiment)' experiment"
	@mkdir -p generated
	@echo $(experiment) > generated/.experiment_name

	# Prepare secrets.
	@echo "==> Preparing secrets"
	@kubectl create secret generic ias \
		--from-file=spid=../../keys/attestation/spid \
		--from-file=pkcs12=../../keys/attestation/client.pfx

	# Generate token file.
	@echo "==> Generating generated/$(experiment).yaml file"
	@echo "### Note: This file was auto-generated from ../custer.yaml." > generated/$(experiment).yaml
	@sed 's/$$BENCHMARK/$(experiment)/g' cluster.yaml | tail -n +3 >> generated/$(experiment).yaml

	@echo "==> Deploying nodes for benchmark"
	@kubectl create -f generated/$(experiment).yaml

destroy:
	$(eval experiment = `cat generated/.experiment_name`)
	@echo "Destroying $(experiment) experiment"

	@echo "==> Destroying nodes"
	@kubectl delete --ignore-not-found=true --now=true --force=true -f generated/$(experiment).yaml
	@kubectl delete --ignore-not-found=true --now=true --force=true pvc -l app=ekiden-benchmark
	@kubectl delete --ignore-not-found=true --now=true --force=true pod ekiden-$(experiment)-benchmark

	@echo "==> Destroying secrets"
	@kubectl delete --ignore-not-found=true --now=true --force=true secret ias

benchmark:
	$(eval experiment = `cat generated/.experiment_name`)
	@echo "==> Running benchmarks for $(experiment)"
	@./benchmark.sh $(experiment)

.PHONY: create destroy benchmark

check-valid-experiment:
	@ if [ "$(experiment)" = "" ]; then \
        echo "You forgot to specify experiment=[$(EXPERIMENTS)]"; \
		exit 1; \
	fi

	@ if ! [[ "$(EXPERIMENTS)" =~ "$(experiment)" ]]; then \
		echo "Invalid experiment name '$(experiment)'. Valid values are: $(EXPERIMENTS)"; \
		exit 1; \
	fi
