all:

update:
	# Generate oasis-node/metrics.md.
	../go/extra/extract-metrics/extract-metrics --codebase.path ../go/ --markdown --markdown.template.file oasis-node/metrics.md.tpl > oasis-node/metrics.md

.PHONY:
	all
	update
