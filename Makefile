PDFLATEX ?= pdflatex
PYTHON ?= python3
PDF_JOBS ?= 4
INSTALL ?= install
CODEX ?= /usr/bin/codex

# Arch Linux dependency manifest (the only supported local host for now).
#
#   make, /bin/sh, find, sort and core utilities (cat, install, mkdir, mv, rm):
#     make bash findutils coreutils
#   Python >= 3.10 and the version-locked site renderer:
#     python python-markdown (exact version in requirements-site.txt)
#   pdflatex, kpsewhich and every directly loaded class/package/font:
#     texlive-bin texlive-basic texlive-latex texlive-latexrecommended
#     texlive-latexextra texlive-pictures texlive-fontsrecommended
#     article, geometry, fontenc, inputenc, lmodern, microtype, array,
#     booktabs, longtable, tabularx, enumitem, needspace, multicol, xcolor,
#     hyperref, tcolorbox, tikz/PGF, graphicx, wrapfig, ragged2e, titlesec,
#     fancyhdr, siunitx and pdflscape
#   repository and isolated-agent workflow:
#     git openai-codex
ARCH_CORE_PACKAGES := make bash findutils coreutils
ARCH_PYTHON_PACKAGES := python python-markdown
ARCH_TEX_PACKAGES := texlive-bin texlive-basic texlive-latex \
	texlive-latexrecommended texlive-latexextra texlive-pictures \
	texlive-fontsrecommended
ARCH_WORKFLOW_PACKAGES := git openai-codex
ARCH_DEPENDENCY_PACKAGES := $(ARCH_CORE_PACKAGES) $(ARCH_PYTHON_PACKAGES) \
	$(ARCH_TEX_PACKAGES) $(ARCH_WORKFLOW_PACKAGES)

SOURCE_ROOT := src
BUILD_ROOT := build
DOC_ROOT := doc
SITE_TOOL := scripts/site

# A document leaf is any directory below src/ holding a main.tex. src/common
# holds only shared includes and never becomes a document.
MAIN_SOURCES := $(shell find $(SOURCE_ROOT) -type f -name main.tex 2>/dev/null | sort)
DOCUMENTS := $(patsubst $(SOURCE_ROOT)/%/main.tex,%,$(MAIN_SOURCES))
BUILD_PDFS := $(addprefix $(BUILD_ROOT)/,$(addsuffix .pdf,$(DOCUMENTS)))
DOC_PDFS := $(addprefix $(DOC_ROOT)/,$(addsuffix .pdf,$(DOCUMENTS)))
COMMON_SOURCES := $(shell find $(SOURCE_ROOT)/common -type f 2>/dev/null | sort)

# Everything a project's documents may share: shared TeX, shared art, and the
# project-wide data tables. Any change to these rebuilds that project's leaves.
PROJECTS := $(sort $(foreach document,$(DOCUMENTS),$(firstword $(subst /, ,$(document)))))

# Telos consumes the reusable Worktree Marshal Make API directly on its frozen
# generic profile. Target names stay plain; lifecycle IDs arrive only as
# validated RUN=<run-id> command-line assignments.
override WORKTREE_MARSHAL := $(CODEX)
override WORKTREE_MARSHAL_DISPLAY_NAME := Telos Codex
include tools/worktree-marshal/src/worktree_marshal/resources/worktree-marshal.mk

.DEFAULT_GOAL := all

# A top-level invocation without -j has no jobserver for document builds to
# share. Bootstrap the aggregate build with a bounded recursive Make in that
# case; if a caller already supplied -j, keep the whole graph in this process.
override _TELOS_MAKE_PARALLEL_FLAGS := $(filter -j% j% --jobs% --jobserver-auth=% --jobserver-fds=%,$(MAKEFLAGS))
override _telos_strip_decimal = $(subst 9,,$(subst 8,,$(subst 7,,$(subst 6,,$(subst 5,,$(subst 4,,$(subst 3,,$(subst 2,,$(subst 1,,$(subst 0,,$(1)))))))))))
override _TELOS_PDF_JOBS_INVALID = $(strip \
	$(call _telos_strip_decimal,$(PDF_JOBS)) \
	$(if $(strip $(PDF_JOBS)),,empty) \
	$(if $(subst 0,,$(strip $(PDF_JOBS))),,zero))
override _TELOS_BOUNDED_PDF_JOB_OPTION = $(if $(strip $(_TELOS_MAKE_PARALLEL_FLAGS)),,\
	$(if $(_TELOS_PDF_JOBS_INVALID),$(error PDF_JOBS requires a positive integer),--jobs=$(PDF_JOBS)))

.PHONY: all pdf install list projects help clean distclean check-tools check \
	doc install-doc site site-preview verify-site \
	dependencies-arch install-dependencies-arch
.DELETE_ON_ERROR:

ifeq ($(strip $(_TELOS_MAKE_PARALLEL_FLAGS)),)
all:
	+@$(MAKE) --no-print-directory $(_TELOS_BOUNDED_PDF_JOB_OPTION) pdf
else
all: pdf
endif

pdf: check-tools $(BUILD_PDFS)

# Promote reviewed builds into the tracked doc/ tree that the site publishes.
install: check-tools $(DOC_PDFS)

list:
	@printf '%s\n' $(DOCUMENTS)

projects:
	@printf '%s\n' $(PROJECTS)

# Single-document convenience wrappers: make doc DOC=<id>
doc:
	@if [ -z '$(DOC)' ]; then \
		echo 'doc requires DOC=<document id below src/>; see make list' >&2; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory '$(BUILD_ROOT)/$(DOC).pdf'

install-doc: doc
	@$(MAKE) --no-print-directory '$(DOC_ROOT)/$(DOC).pdf'

site:
	@$(PYTHON) $(SITE_TOOL) build

site-preview:
	@$(PYTHON) $(SITE_TOOL) build --serve

verify-site:
	@$(PYTHON) $(SITE_TOOL) verify

check: check-tools
	@$(PYTHON) $(SITE_TOOL) check

dependencies-arch:
	@printf '%s\n' $(ARCH_DEPENDENCY_PACKAGES)

# Arch does not support partial upgrades: synchronize and upgrade in the same
# transaction that installs the canonical packages.
install-dependencies-arch:
	@set -eu; \
	if [ "$$(id -u)" = 0 ]; then \
		pacman -Syu --needed -- $(ARCH_DEPENDENCY_PACKAGES); \
	else \
		sudo pacman -Syu --needed -- $(ARCH_DEPENDENCY_PACKAGES); \
	fi

help:
	@printf '%s\n' \
		'Telos — home project publications' \
		'' \
		'make            Build every document PDF into build/' \
		'make list       List document ids' \
		'make projects   List project ids' \
		'make doc DOC=<id>          Build one document' \
		'make install-doc DOC=<id>  Build and promote one document into doc/' \
		'make install    Promote every reviewed build into doc/' \
		'make site       Render the GitHub Pages artifact into build/site' \
		'make site-preview          Render and serve it on localhost' \
		'make verify-site           Re-check the rendered artifact' \
		'make check      Validate the site manifest against the tree' \
		'make clean      Remove build/' \
		'' \
		'Isolated agent runs (Worktree Marshal):' \
		'make codex                 Start an isolated run' \
		'make status [RUN=<id>]     Show run state' \
		'make reopen RUN=<id>       Reopen a retained run' \
		'make final-diff RUN=<id>   Show the reviewable diff' \
		'make integrate RUN=<id>    Land a reviewed run' \
		'make abort RUN=<id>        Discard a run'

# Register every render-capable file owned by a document leaf so editing any of
# them recompiles exactly that leaf.
define REGISTER_DOCUMENT_SOURCES
$(BUILD_ROOT)/$(1).pdf: $(shell find $(SOURCE_ROOT)/$(1) -type f \( \
	-name '*.tex' -o -name '*.sty' -o -name '*.cls' -o -name '*.png' -o \
	-name '*.jpg' -o -name '*.jpeg' -o -name '*.pdf' -o -name '*.eps' \) 2>/dev/null | sort)
endef
$(foreach document,$(DOCUMENTS),$(eval $(call REGISTER_DOCUMENT_SOURCES,$(document))))

# Every leaf in a project also depends on that project's shared includes and art.
define REGISTER_PROJECT_SHARED
$(filter $(BUILD_ROOT)/$(1)/%,$(BUILD_PDFS)): $(shell find $(SOURCE_ROOT)/$(1)/shared -type f \( \
	-name '*.tex' -o -name '*.sty' -o -name '*.png' -o -name '*.jpg' -o \
	-name '*.jpeg' -o -name '*.pdf' -o -name '*.eps' \) 2>/dev/null | sort)
endef
$(foreach project,$(PROJECTS),$(eval $(call REGISTER_PROJECT_SHARED,$(project))))

# Build from the leaf directory so a document's own art resolves by plain
# relative name, with src/ on TEXINPUTS for common/ and the project's shared/.
$(BUILD_ROOT)/%.pdf: $(SOURCE_ROOT)/%/main.tex $(COMMON_SOURCES)
	@mkdir -p $(@D)
	cd $(SOURCE_ROOT)/$* && TEXINPUTS=.:$(abspath $(SOURCE_ROOT)): \
		$(PDFLATEX) -interaction=nonstopmode -halt-on-error \
		-jobname=$(notdir $*) -output-directory=$(abspath $(@D)) main.tex
	cd $(SOURCE_ROOT)/$* && TEXINPUTS=.:$(abspath $(SOURCE_ROOT)): \
		$(PDFLATEX) -interaction=nonstopmode -halt-on-error \
		-jobname=$(notdir $*) -output-directory=$(abspath $(@D)) main.tex

$(DOC_ROOT)/%.pdf: $(BUILD_ROOT)/%.pdf
	@mkdir -p $(@D)
	@$(INSTALL) -m 0644 -- '$<' '$@'

check-tools:
	@command -v $(PDFLATEX) >/dev/null || { echo "Missing $(PDFLATEX)"; exit 1; }
	@command -v $(PYTHON) >/dev/null || { echo "Missing $(PYTHON)"; exit 1; }
	@command -v $(INSTALL) >/dev/null || { echo "Missing $(INSTALL)"; exit 1; }

clean:
	rm -rf $(BUILD_ROOT)

distclean: clean

# The per-lake compendiums bind already-built sheets with \includepdf, so they
# depend on every other PDF in the project rather than on TeX sources.
COMPENDIUM_PDFS := $(filter $(BUILD_ROOT)/lake-country-fishing/compendium/%,$(BUILD_PDFS))
COMPENDIUM_INPUTS := $(filter-out $(COMPENDIUM_PDFS),\
	$(filter $(BUILD_ROOT)/lake-country-fishing/%,$(BUILD_PDFS)))
$(COMPENDIUM_PDFS): $(COMPENDIUM_INPUTS)
