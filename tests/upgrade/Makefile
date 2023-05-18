include ../../common.mk

# Go modules.
modules := pre post

# Set all target as the default target.
all: build

# Build.
build:
	@$(ECHO) "$(CYAN)*** Building Go modules ($(modules))...$(OFF)"
	@$(foreach module,$(modules),$(MAKE) -C $(module) build &&) true

# Format code.
fmt:
	@$(ECHO) "$(CYAN)*** Formatting Go modules ($(modules))...$(OFF)"
	@$(foreach module,$(modules),$(MAKE) -C $(module) fmt &&) true

# Lint.
lint:
	@$(ECHO) "$(CYAN)*** Linting Go modules ($(modules))...$(OFF)"
	@$(foreach module,$(modules),$(MAKE) -C $(module) lint &&) true

lint-mod-tidy:
	@$(ECHO) "$(CYAN)*** Checking go mod tidy on Go modules ($(modules))...$(OFF)"
	@$(foreach module,$(modules),$(MAKE) -C $(module) lint-mod-tidy &&) true

# Clean.
clean:
	@$(ECHO) "$(CYAN)*** Cleaning Go modules ($(modules))...$(OFF)"
	@$(foreach module,$(modules),$(MAKE) -C $(module) clean &&) true

# List of targets that are not actual files.
.PHONY: \
	$(modules) build \
	fmt lint lint-mod-tidy \
	clean all

.FORCE:
