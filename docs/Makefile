all:

check:
	@# Check whether update-docs are up to date.
	@../go/extra/extract-metrics/extract-metrics --codebase.path ../go/ --markdown --markdown.template.file oasis-node/metrics.md.tpl | diff oasis-node/metrics.md -

update:
	@# Generate oasis-node/metrics.md.
	@../go/extra/extract-metrics/extract-metrics --codebase.path ../go/ --markdown --markdown.template.file oasis-node/metrics.md.tpl > oasis-node/metrics.md

.PHONY:
	all
	check
	update
