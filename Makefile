PDFLATEX ?= pdflatex
GHOSTSCRIPT ?= gs
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
	texlive-fontsrecommended ghostscript
ARCH_WORKFLOW_PACKAGES := git openai-codex
# Homelab provisioning: image build, disk layout and the QEMU acceptance matrix.
#
# qemu-base, deliberately, and never qemu-desktop or qemu-full. Those pull in
# qemu-audio-jack, which depends on the virtual package `jack` -- provided by
# both jack2 and pipewire-jack -- so pacman stops mid-transaction and asks which
# one to use, and pipewire-jack then depends on the virtual
# pipewire-session-manager, so answering earns another question. The lab runs
# headless (-nographic, -nodefaults, no audio device at all), so none of that
# branch is wanted. `make check` verifies the closure stays free of it.
ARCH_HOMELAB_PACKAGES := archiso gptfdisk btrfs-progs cryptsetup dosfstools \
	dnsmasq nginx ipxe qemu-base edk2-ovmf ansible
# Explicit choices for virtual dependencies that more than one package could
# satisfy. Naming a provider here settles it before pacman has to ask. Empty
# because the list above needs nothing: keep it that way rather than growing it.
ARCH_PROVIDER_PACKAGES :=
ARCH_DEPENDENCY_PACKAGES := $(ARCH_CORE_PACKAGES) $(ARCH_PYTHON_PACKAGES) \
	$(ARCH_TEX_PACKAGES) $(ARCH_WORKFLOW_PACKAGES) \
	$(ARCH_HOMELAB_PACKAGES) $(ARCH_PROVIDER_PACKAGES)

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
	homelab-test homelab-lab homelab-matrix homelab-image \
	homelab-converge-check \
	homelab-instance adr-digest \
	dependencies-arch install-dependencies-arch check-dependencies-arch
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
	@$(PYTHON) scripts/research-library
	@$(PYTHON) scripts/arch-packages --check
	@$(PYTHON) -m unittest discover -s tests -t . -q
	@cd homelab && $(PYTHON) -m unittest discover -s tests -t . -q

# Homelab: the tests are pure Python and need nothing installed; the lab needs
# QEMU and OVMF and says so when they are absent.
homelab-test:
	@cd homelab && $(PYTHON) -m unittest discover -s tests -t . -v

homelab-lab:
	@cd homelab && $(PYTHON) -c "import sys; sys.path.insert(0,'qemu'); import lab; \
		missing = lab.missing_requirements(); \
		print('lab ready') if not missing else \
		[print('missing:', item) for item in missing]"

# Stage the provisioning image and print the privileged build command. Nothing
# here runs as root: mkarchiso needs it, and granting it is the operator's call.
homelab-image:
	@cd homelab && $(PYTHON) bin/homelab-image

# The acceptance matrix. Stage 1 runs today; the rest report what they are
# waiting for rather than passing silently.
homelab-matrix:
	@cd homelab && $(PYTHON) qemu/matrix.py

# Seed the private instance overlay from the tracked template. Never overwrites:
# the overlay is not in Git, so clobbering it loses the only copy.
homelab-instance:
	@if [ -d homelab/instance ]; then \
		echo "homelab/instance already exists, leaving it alone"; \
	else \
		cp -r homelab/instance-example homelab/instance; \
		echo "seeded homelab/instance from the template; fill in the placeholders"; \
	fi

# Syntax-check the convergence playbooks. Structural invariants are covered by
# the unit tests; this catches what only Ansible itself can see. Skips quietly
# where Ansible is not installed.
homelab-converge-check:
	@if command -v ansible-playbook >/dev/null 2>&1; then \
		cd homelab/ansible && for play in playbooks/*.yml; do \
			ansible-playbook --syntax-check -i localhost, "$$play" || exit 1; \
		done; \
	else \
		echo "ansible-playbook not installed, playbooks not syntax-checked"; \
	fi

# Regenerate the printable decision record from the Markdown ADRs.
adr-digest:
	@$(PYTHON) scripts/adr-digest

dependencies-arch:
	@printf '%s\n' $(ARCH_DEPENDENCY_PACKAGES)

# Verify the declared closure needs no provider disambiguation. Skips quietly
# on a host with no pacman databases.
check-dependencies-arch:
	@$(PYTHON) scripts/arch-packages --check

# Arch does not support partial upgrades: synchronize and upgrade in the same
# transaction that installs the canonical packages.
#
# The declared closure is checked first so a run cannot stall on a provider
# question. --noconfirm then keeps the transaction moving; note that pacman's
# default answer to "remove conflicting package?" is no, so a genuine conflict
# still aborts rather than silently uninstalling something.
install-dependencies-arch: check-dependencies-arch
	@set -eu; \
	if [ "$$(id -u)" = 0 ]; then \
		pacman -Syu --needed --noconfirm -- $(ARCH_DEPENDENCY_PACKAGES); \
	else \
		sudo pacman -Syu --needed --noconfirm -- $(ARCH_DEPENDENCY_PACKAGES); \
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
		'make check      Validate the site manifest and run the homelab tests' \
		'make homelab-test         Run the homelab suite verbosely' \
		'make homelab-lab          Report whether the QEMU lab can run' \
		'make adr-digest           Regenerate the printable decision record' \
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

# Every leaf in a project also depends on that project's provider-owned shared
# includes and art. Provider trees are deliberately free to organize
# themselves differently; recursively finding shared/ directories avoids
# imposing one cross-provider document shape.
define REGISTER_PROJECT_SHARED
$(filter $(BUILD_ROOT)/$(1)/%,$(BUILD_PDFS)): $(shell find $(SOURCE_ROOT)/$(1) -type f -path '*/shared/*' \( \
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
	@if [ '$(filter lake-country-fishing/chatgpt/compendium/%,$*)' ]; then \
		$(GHOSTSCRIPT) -sDEVICE=pdfwrite -dCompatibilityLevel=1.7 \
			-dPDFSETTINGS=/prepress -dDetectDuplicateImages=true \
			-dColorImageDownsampleType=/Bicubic -dColorImageResolution=200 \
			-dGrayImageDownsampleType=/Bicubic -dGrayImageResolution=200 \
			-dMonoImageDownsampleType=/Subsample -dMonoImageResolution=600 \
			-sColorConversionStrategy=Gray -dProcessColorModel=/DeviceGray \
			-dNOPAUSE -dQUIET -dBATCH -sOutputFile='$@.optimized' '$@'; \
		mv -- '$@.optimized' '$@'; \
	fi

$(DOC_ROOT)/%.pdf: $(BUILD_ROOT)/%.pdf
	@mkdir -p $(@D)
	@$(INSTALL) -m 0644 -- '$<' '$@'

check-tools:
	@command -v $(PDFLATEX) >/dev/null || { echo "Missing $(PDFLATEX)"; exit 1; }
	@command -v $(GHOSTSCRIPT) >/dev/null || { echo "Missing $(GHOSTSCRIPT)"; exit 1; }
	@command -v $(PYTHON) >/dev/null || { echo "Missing $(PYTHON)"; exit 1; }
	@command -v $(INSTALL) >/dev/null || { echo "Missing $(INSTALL)"; exit 1; }

clean:
	rm -rf $(BUILD_ROOT)

distclean: clean

# Each provider's per-lake compendiums bind that provider's already-built
# sheets with \includepdf. Keep the dependency inside the edition: a ChatGPT
# compendium must not wait on, or accidentally bind, Claude artifacts.
COMPENDIUM_EDITIONS := $(sort $(foreach document,$(DOCUMENTS),\
	$(if $(findstring /compendium/,$(document)),\
	$(word 1,$(subst /, ,$(document)))/$(word 2,$(subst /, ,$(document))))))
define REGISTER_COMPENDIUM_EDITION
$(filter $(BUILD_ROOT)/$(1)/compendium/%,$(BUILD_PDFS)): \
	$(filter-out $(BUILD_ROOT)/$(1)/compendium/%,\
	$(filter $(BUILD_ROOT)/$(1)/%,$(BUILD_PDFS)))
endef
$(foreach edition,$(COMPENDIUM_EDITIONS),$(eval $(call REGISTER_COMPENDIUM_EDITION,$(edition))))
