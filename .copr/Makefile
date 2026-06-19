.PHONY: deps srpm
.DEFAULT_GOAL := srpm

DOT_COPR := $(dir $(firstword $(MAKEFILE_LIST)))
TOP_DIR := $(realpath $(DOT_COPR)/../)

RPM_DIR := $(TOP_DIR)/rpm
outdir ?= $(RPM_DIR)/SRPMS

HAS_GIT := $(shell command -v git 2> /dev/null)
ifndef HAS_GIT
deps:
	dnf -y install git
else
deps:
endif

srpm: deps
	git config --global --add safe.directory $(TOP_DIR)
	git config --global --add safe.directory $(TOP_DIR)/libbloom
	git config --global --add safe.directory $(TOP_DIR)/libcork
	git config --global --add safe.directory $(TOP_DIR)/libipset
	$(RPM_DIR)/genrpm.sh -o $(outdir)
