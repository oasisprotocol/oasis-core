IMG_ORG ?= ekiden
IMG_VER ?= latest

IMAGES = development testing

.PHONY: all $(IMAGES)

all: $(IMAGES)

development: development/Dockerfile
	docker build $@ -t $(IMG_ORG)/$@:$(IMG_VER) -f $<

testing: testing/Dockerfile development/Dockerfile
	docker build $@ -t $(IMG_ORG)/$@:$(IMG_VER) -f $<
