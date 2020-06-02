IMG_ORG ?= oasisprotocol
IMG_VER ?= master

IMAGES = oasis-core-dev oasis-core-ci

.PHONY: all $(IMAGES)

all: $(IMAGES)

oasis-core-dev: development/Dockerfile
	docker build $@ -t $(IMG_ORG)/$@:$(IMG_VER)

oasis-core-ci: testing/Dockerfile development/Dockerfile
	docker build --build-arg OASIS_CORE_DEV_BASE_TAG=$(IMG_VER) $@ -t $(IMG_ORG)/$@:$(IMG_VER)
