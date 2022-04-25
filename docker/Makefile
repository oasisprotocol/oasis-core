IMG_ORG ?= oasisprotocol
IMG_VER ?= master

IMAGES = oasis-core-dev oasis-core-ci aesmd

.PHONY: all $(IMAGES)

all: $(IMAGES)

oasis-core-dev: oasis-core-dev/Dockerfile
	docker build $@ -t $(IMG_ORG)/$@:$(IMG_VER)

oasis-core-ci: oasis-core-ci/Dockerfile oasis-core-dev/Dockerfile
	docker build --build-arg OASIS_CORE_DEV_BASE_TAG=$(IMG_VER) $@ -t $(IMG_ORG)/$@:$(IMG_VER)

aesmd: aesmd/Dockerfile
	docker build $@ -t $(IMG_ORG)/$@:$(IMG_VER)
