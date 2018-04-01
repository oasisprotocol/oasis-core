create:
	@echo "==> Deploying nodes"
	@kubectl create -f ethermint.yaml

destroy:
	@echo "==> Destroying nodes"
	@kubectl delete --ignore-not-found=true --now=true --force=true -f ethermint.yaml
	@kubectl delete --ignore-not-found=true --now=true --force=true pvc -l app=ethermint

benchmark:
	@echo "==> Running benchmarks"
	@./benchmark.sh

.PHONY: create destroy benchmark
