IMG_ORG ?= ekiden
IMG_VER ?= latest

IMAGES = development testing migration

.PHONY: all $(IMAGES)

all: $(IMAGES)

development: development/Dockerfile
	docker build $@ -t $(IMG_ORG)/$@:$(IMG_VER)

testing: testing/Dockerfile development/Dockerfile
	docker build $@ -t $(IMG_ORG)/$@:$(IMG_VER)

migration: migration/Dockerfile migration/context.tar
	cat migration/context.tar | docker build - -t $(IMG_ORG)/$@:$(IMG_VER)

# warning: dependencies are approximate
migration/context.tar: ../scripts/storage/export.py ../scripts/storage/import.py ../scripts/roothash/export.py ../scripts/roothash/list-runtimes.py
	$(MAKE) -C ../scripts/storage
	$(MAKE) -C ../scripts/roothash
	tar -cvf $@.tmp -C ../scripts storage roothash
	tar -rvf $@.tmp -C migration Dockerfile
	mv $@.tmp $@
