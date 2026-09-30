PDFLATEX ?= pdflatex
GHOSTSCRIPT ?= gs
PYTHON ?= python3
PDF_JOBS ?= 4
INSTALL ?= install
CODEX ?= /usr/bin/codex
READING_LIST_SOURCE := Reading.List.ods
READING_LIST_TOOL := scripts/reading-list.py
READING_LIST_YAML := site/data/reading-list.yaml
READING_LIST_JSON := site/data/reading-list.json
READING_LIST_GENRES := site/data/reading-genres.yaml

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
	dnsmasq nginx ipxe qemu-base edk2-ovmf ansible samba krb5 ntp \
	python-cryptography python-dnspython python-pexpect openresolv bind \
	openssh rsync gnupg fakeroot mtools util-linux \
	wimlib libisoburn 7zip
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
ARCH_ISO ?= homelab/var/media/arch/archlinux-x86_64.iso
WINDOWS_ISO_CACHE ?= homelab/var/media/windows/windows-11-x64.iso
WINDOWS_INSTALL_SOURCE ?= homelab/var/media/windows/install-source
FACTORY_MEDIA_SEAL ?= homelab/var/media/factory-media-seal.json
FACTORY_ARCH_SOURCE_CACHE ?= homelab/var/media/arch/extracted
WORKSTATION_REPO ?= homelab/var/media/arch/workstation-repo
# A Controller release needs a purpose-built mkarchiso netboot tree. The
# convergence seed is a data disc and is never substituted for this payload.
FACTORY_CONTROLLER_SOURCE ?= homelab/var/media/controller/netboot
WINDOWS_25H2_EN_US_ISO ?= Win11_25H2_English_x64_v2.iso
WINDOWS_25H2_EN_US_SHA256 := 768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3
WINDOWS_INSTALL_SHA256 ?= $(WINDOWS_25H2_EN_US_SHA256)
WIMBOOT ?= homelab/var/media/wimboot
SIM_CYCLES ?= 2
FACTORY_CONTROLLER_BUNDLE ?= homelab/var/factory/controller-convergence.iso
FACTORY_DURATION ?= 120
FACTORY_RELEASES ?=
FACTORY_TARGET ?= arch-workstation
# Gate 12 (repeatability): the second twice-through run's retained evidence,
# compared against FACTORY_EVIDENCE by homelab-factory-verify.
FACTORY_COMPARE_EVIDENCE ?=
# Gate 12 (repeatability): the aggregate repeat driver's roots, iteration count
# and optional receipt. FACTORY_DURATION is the per-phase budget it forwards
# into each phase, so raise it well above the 120s default for a real run.
REPEAT_EVIDENCE_ROOT ?= homelab/var/factory/repeat
REPEAT_WORK_ROOT ?= homelab/var/factory/repeat-work
REPEAT_ITERATIONS ?= 2
REPEAT_RECEIPT ?=
# Persistent controller instances: a directory server that can be brought up,
# used, shut down, and brought up again with the same domain and accounts. This
# is NOT the acceptance path. Every gate still boots a disposable copy of
# FACTORY_CONTROLLER_STATE and hash-fences it, so a persistent instance always
# lives under its own root and the tooling refuses the canonical acceptance
# state outright. PERSISTENT_DC is the stable instance name and has no default:
# persistence must be asked for by name, never inferred.
PERSISTENT_DC_ROOT ?= build/homelab/vm/persistent-dc
PERSISTENT_DC ?=
# A kept (durable) workstation, TASK-28: named by WORKSTATION, never inferred,
# and bound to one persistent instance. Its disk, marker and stage ledger live
# under DURABLE_WORKSTATION_ROOT, beside persistent-dc and outside the
# bulk-cleaned homelab/var/factory.
DURABLE_WORKSTATION_ROOT ?= build/homelab/vm/workstations
WORKSTATION ?=
# Lifecycle recovery (gate 11). All three were used by the recipes below long
# before they were declared here, which made a reader guess at their shape.
# RECOVERY_RUN names a fresh run-bundle directory and has no default: a
# recovery run must be aimed deliberately. RECOVERY_BOOT is a non-empty opt-in
# that forwards --boot, so the default costs no guest boot. RECOVERY_EVIDENCE
# names an already-produced recovery-evidence.jsonl for the read-only judge.
RECOVERY_RUN ?=
RECOVERY_BOOT ?=
RECOVERY_EVIDENCE ?=

# Both empty by default so the convergence keeps its own long in-guest bound and
# never reconverges by accident. FACTORY_DURATION is deliberately NOT reused: its
# 120-second default would abort a Samba provisioning run.
PERSISTENT_CONVERGE_TIMEOUT ?=
RECONVERGE ?=
# The owner's private identity overlay, for the durable-account verb only.
# Optional: with no value the roster resolves from
# homelab/instance/identity/principals.json, which is where it belongs. It
# carries NAMES and never a credential.
IDENTITY_OVERLAY ?=
# The permanent directory identity document (ADR 0065). Optional: with no
# value it resolves from homelab/instance/identity/directory.json, which is
# where it belongs. The durable path REFUSES to inherit the acceptance realm.
DIRECTORY_IDENTITY ?=
# Stage the durable roster again after an unfinished or a completed run. It
# does NOT reset the password of an account the directory already holds.
RESTAGE ?=
PERSISTENT_ACCOUNTS_TIMEOUT ?=
# Complete a persistent instance's recorded domain SID when it is a strict
# prefix of the live one (the split-read truncation fixed in 05eec6e). Any other
# difference is still refused, and nothing is written unless the probe passes.
REPAIR_SID ?=

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
	init-aiq init-tmt \
	reading-list \
	reading-list-scan \
	homelab-test homelab-check homelab-lab homelab-matrix homelab-image \
	homelab-converge-check homelab-bootstrap-deps \
	homelab-media homelab-media-arch homelab-media-windows \
	homelab-media-windows-25h2-en-us \
	homelab-media-workstation-repo \
	homelab-stage-windows-source \
	homelab-media-wimboot homelab-bootstrap-seed \
	homelab-bootstrap-vm-plan homelab-bootstrap-vm-status \
	homelab-bootstrap-vm-create homelab-bootstrap-vm-run \
	homelab-bootstrap-vm-boot homelab-bootstrap-vm-destroy \
	homelab-bootstrap-vm-install \
	homelab-bootstrap-network-preflight homelab-bootstrap-network-plan \
	homelab-bootstrap-network-host-plan homelab-bootstrap-network-host-prepare \
	homelab-bootstrap-network-receipt homelab-bootstrap-network-authorize \
	homelab-bootstrap-network-run homelab-bootstrap-network-check \
	homelab-bootstrap-network-teardown \
	homelab-sim-plan homelab-sim-run homelab-sim-check \
	homelab-sim-repeat homelab-sim-deps \
	homelab-sim-auto-plan homelab-sim-auto-run homelab-sim-auto-repeat \
	homelab-bootstrap-controller \
	homelab-pxe-controller homelab-pxe-arch homelab-pxe-windows \
	homelab-pxe-all homelab-pxe-release-set homelab-pxe-release-set-verify \
	homelab-pxe-release-set-rollback homelab-pxe-test homelab-pxe-verify \
	homelab-pxe-publish homelab-pxe-rollback \
	homelab-workstation-plan homelab-workstation-verify \
	homelab-arch-update-check homelab-arch-update-test \
	homelab-factory-deps homelab-factory-media \
	homelab-factory-cache-seal homelab-factory-offline-check \
	homelab-factory-controller-bundle homelab-factory-pxe \
	homelab-factory-verify homelab-factory-repeat homelab-pxe-authority-audit \
	homelab-factory-recover homelab-factory-recover-judge \
	homelab-factory-sim-plan homelab-factory-sim-run \
	homelab-factory-persistent-plan homelab-factory-persistent-status \
	homelab-factory-persistent-up homelab-factory-persistent-converge \
	homelab-factory-persistent-converge-plan \
	homelab-factory-persistent-destroy \
	homelab-factory-persistent-accounts-plan \
	homelab-factory-persistent-accounts \
	homelab-factory-persistent-probe \
	homelab-durable-workstation-plan homelab-durable-workstation-status \
	homelab-durable-workstation-adopt homelab-durable-workstation-destroy \
	homelab-windows-install-prepare \
	homelab-windows-install-run \
	homelab-arch-install-prepare homelab-arch-install-run \
	homelab-arch-identity-prepare homelab-arch-identity-run \
	homelab-arch-identity-judge \
	homelab-dualboot-acceptance-prepare homelab-dualboot-acceptance-run \
	homelab-dualboot-acceptance-judge \
	homelab-windows-identity-prepare \
	homelab-windows-identity-run \
	homelab-windows-identity-judge \
	homelab-image-promotion-gate \
	homelab-private-bootstrap homelab-private-onboard homelab-private-check \
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

reading-list:
	@if [ -f '$(READING_LIST_SOURCE)' ]; then \
		$(PYTHON) $(READING_LIST_TOOL) --source '$(READING_LIST_SOURCE)' ingest \
			--delete-source --yaml $(READING_LIST_YAML) --json $(READING_LIST_JSON); \
		$(PYTHON) $(READING_LIST_TOOL) --yaml $(READING_LIST_YAML) --json $(READING_LIST_JSON) \
			--genres $(READING_LIST_GENRES) scan; \
	elif [ -f '$(READING_LIST_YAML)' ] && [ -f '$(READING_LIST_JSON)' ]; then \
		printf '%s\n' 'reading-list: source already ingested; using generated data'; \
	else \
		echo 'reading-list: missing source and generated output; place Reading.List.ods in repo root and retry' >&2; \
		exit 1; \
	fi

reading-list-scan:
	@if [ -f '$(READING_LIST_JSON)' ] && [ -f '$(READING_LIST_GENRES)' ]; then \
		$(PYTHON) $(READING_LIST_TOOL) --yaml $(READING_LIST_YAML) --json $(READING_LIST_JSON) \
			--genres $(READING_LIST_GENRES) scan; \
	else \
		echo 'reading-list-scan: missing $(READING_LIST_JSON) or $(READING_LIST_GENRES)' >&2; \
		exit 1; \
	fi

# Bring this checkout's local AIQ work ledger and its owned guidance block up
# to date. Both steps are idempotent: init validates an existing journal, and
# the guidance integration reports no action when the block is already current.
# Ledger state lives in .git/aiq/ and is never committed.
init-aiq:
	@command -v aiq >/dev/null 2>&1 || { \
		echo 'init-aiq: aiq not found on PATH; install it from ../aiq' >&2; \
		exit 1; \
	}
	@aiq journal init
	@aiq integration install guidance --target '$(CURDIR)/AGENTS.md'
	@aiq doctor

# Create the tool registry when absent, refresh the AGENTS.md habit block, and
# gate the result. tmt init refuses an existing registry, so it is conditional
# while the other two steps are safe to repeat.
init-tmt:
	@command -v tmt >/dev/null 2>&1 || { \
		echo 'init-tmt: tmt not found on PATH; install it from ../tmt' >&2; \
		exit 1; \
	}
	@if [ ! -f tmt.json ]; then tmt init; fi
	@tmt agents --write
	@tmt check

site:
	@$(MAKE) reading-list
	@$(PYTHON) $(SITE_TOOL) build

site-preview:
	@$(PYTHON) $(SITE_TOOL) build --serve

verify-site:
	@$(PYTHON) $(SITE_TOOL) verify

check: check-tools
	@$(PYTHON) $(SITE_TOOL) check
	@tools/doc-make-target-drift
	@$(PYTHON) scripts/research-library
	@$(PYTHON) scripts/arch-packages --check
	@$(PYTHON) -m unittest discover -s tests -t . -q
	@$(PYTHON) -m unittest discover -s homelab/tests -t . -q
	@if command -v tmt >/dev/null 2>&1; then tmt check; else \
		echo 'tmt absent: tmt.json registry gate skipped'; fi

# Homelab: the tests are pure Python and need nothing installed; the lab needs
# QEMU and OVMF and says so when they are absent.
homelab-test:
	@$(PYTHON) -m unittest discover -s homelab/tests -t . -v

# The smallest honest verification after a homelab-scoped edit. Unlike
# `check` it needs no TeX toolchain and skips the research gates.
#
# It does NOT skip the site check, despite that gate rendering no homelab page:
# the instance-leak scanner reads homelab/tests/**/*.py, so a synthetic address
# outside the sanctioned ranges in a homelab TEST fixture is a site-check
# failure that homelab-check used to pass over. That happened on 2026-08-18 --
# a lane verified green here and `make check` then refused its fixture. The
# scan costs about half a second, which is nothing against 60s of tests.
homelab-check:
	@tools/doc-make-target-drift
	@$(PYTHON) scripts/site check
	@$(PYTHON) scripts/arch-packages --check
	@$(PYTHON) -m unittest discover -s tests -t . -q
	@$(PYTHON) -m unittest discover -s homelab/tests -t . -q

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

# Install the complete Arch build-host dependency set. This is an explicit
# alias so the workstation manual can name the phase it prepares.
homelab-bootstrap-deps: install-dependencies-arch

# Resolve current upstream media into an ignored cache. Arch is checked against
# its official digest and pinned release key. wimboot is version/hash pinned.
# Microsoft requires an interactive consumer-media link, so the aggregate
# target stops at that explicit gate until the operator supplies its ISO and
# the digest printed by Microsoft's verification table.
homelab-media: homelab-media-arch homelab-media-workstation-repo \
	homelab-media-wimboot homelab-media-windows

homelab-media-arch:
	@homelab/media/fetch-arch

# Resolve the full workstation-install dependency closure through the host's
# signed mirrors with the same machinery as the Controller seed, build a
# pacman repository database, and bind every byte in a receipt. Online;
# acquire phase only. The offline gate and publication re-verify the receipt.
homelab-media-workstation-repo:
	@homelab/bin/homelab-media-workstation-repo build \
		--contract homelab/package-contract.json \
		--repo '$(WORKSTATION_REPO)'

homelab-media-windows:
	@if { [ -n '$(WINDOWS_ISO)' ] && [ -z '$(WINDOWS_SHA256)' ]; } || \
	    { [ -z '$(WINDOWS_ISO)' ] && [ -n '$(WINDOWS_SHA256)' ]; }; then \
		echo 'WINDOWS_ISO and WINDOWS_SHA256 must be supplied together' >&2; \
		exit 2; \
	elif [ -n '$(WINDOWS_ISO)' ] && [ -n '$(WINDOWS_SHA256)' ]; then \
		homelab/bin/homelab-fetch-windows \
			--source '$(WINDOWS_ISO)' --expected-sha256 '$(WINDOWS_SHA256)' \
			--output '$(WINDOWS_ISO_CACHE)'; \
	elif [ -f '$(WINDOWS_25H2_EN_US_ISO)' ]; then \
		$(MAKE) --no-print-directory homelab-media-windows-25h2-en-us; \
	else \
		homelab/bin/homelab-fetch-windows --output '$(WINDOWS_ISO_CACHE)'; \
	fi

homelab-media-windows-25h2-en-us:
	@homelab/bin/homelab-fetch-windows \
		--source '$(WINDOWS_25H2_EN_US_ISO)' \
		--expected-sha256 '$(WINDOWS_25H2_EN_US_SHA256)' \
		--output '$(WINDOWS_ISO_CACHE)'

homelab-stage-windows-source:
	@homelab/bin/homelab-stage-windows-source \
		--iso '$(WINDOWS_ISO_CACHE)' \
		--expected-sha256 '$(WINDOWS_INSTALL_SHA256)' \
		--output '$(WINDOWS_INSTALL_SOURCE)'

homelab-media-wimboot:
	@homelab/bin/homelab-fetch-wimboot --output '$(WIMBOOT)'

# Local factory acquisition is the only aggregate stage allowed to fetch.
# Everything below homelab-factory-cache-seal consumes the ignored cache.
homelab-factory-deps: homelab-bootstrap-deps

homelab-factory-media: homelab-media

homelab-factory-cache-seal:
	@homelab/bin/homelab-media-seal create \
		--seal '$(FACTORY_MEDIA_SEAL)' \
		--arch-iso '$(ARCH_ISO)' \
		--arch-receipt '$(ARCH_ISO).receipt.json' \
		--windows-iso '$(WINDOWS_ISO_CACHE)' \
		--windows-provenance '$(WINDOWS_ISO_CACHE).provenance.json' \
		--windows-verification '$(WINDOWS_ISO_CACHE).verification.json' \
		--windows-install-source '$(WINDOWS_INSTALL_SOURCE)' \
		--wimboot '$(WIMBOOT)' \
		--wimboot-metadata homelab/media/wimboot.json >/dev/null
	@printf '%s\n' 'PASS: local factory media cache is sealed'

homelab-factory-offline-check:
	@homelab/bin/homelab-media-seal verify \
		--seal '$(FACTORY_MEDIA_SEAL)' \
		--arch-iso '$(ARCH_ISO)' \
		--arch-receipt '$(ARCH_ISO).receipt.json' \
		--windows-iso '$(WINDOWS_ISO_CACHE)' \
		--windows-provenance '$(WINDOWS_ISO_CACHE).provenance.json' \
		--windows-verification '$(WINDOWS_ISO_CACHE).verification.json' \
		--windows-install-source '$(WINDOWS_INSTALL_SOURCE)' \
		--wimboot '$(WIMBOOT)' \
		--wimboot-metadata homelab/media/wimboot.json >/dev/null
	@homelab/bin/homelab-media-workstation-repo verify \
		--contract homelab/package-contract.json \
		--repo '$(WORKSTATION_REPO)' >/dev/null
	@printf '%s\n' \
		'PASS: required local inputs verify without acquisition' \
		'Network isolation is enforced by the lifecycle runner, not this cache check.'

# This ISO contains a generated synthetic AD password. It is ignored, mode
# 0600, and must be deleted by the lifecycle runner after controller convergence.
homelab-factory-controller-bundle:
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to build the ephemeral controller bundle'; \
		$(PYTHON) homelab/vm/controller_factory.py --print-guest-command; \
	else \
		$(PYTHON) homelab/vm/controller_factory.py \
			--output '$(FACTORY_CONTROLLER_BUNDLE)'; \
	fi

# Build the three immutable PXE leaves from already-local inputs. Arch is
# extracted without mounting into a digest-addressed ignored cache. A genuine
# Controller mkarchiso netboot tree remains a separate required local artifact.
homelab-factory-pxe: homelab-factory-offline-check
	@if [ -z '$(VERSION)' ]; then \
		echo 'require VERSION=YYYYMMDD.NNN' >&2; \
		exit 2; \
	fi
	@$(MAKE) --no-print-directory homelab-pxe-release-set \
		VERSION='$(VERSION)' \
		CONTROLLER_SOURCE='$(or $(CONTROLLER_SOURCE),$(FACTORY_CONTROLLER_SOURCE))' \
		ARCH_SOURCE='$(ARCH_SOURCE)' \
		BASE_URL='$(or $(BASE_URL),http://10.1.31.2)'

# Validate all retained evidence and produce a machine-readable final receipt.
# Read-only: it never boots, installs, or mutates. The dry run prints the check
# plan; APPLY=1 emits the receipt and a PASS/FAIL/NOT RUN verdict. A recorded
# measurement that is absent stays NOT RUN and is never promoted to a pass.
# FACTORY_COMPARE_EVIDENCE names a second retained run: it renders the gate-12
# repeat verdict, classifying every differing receipt byte as expected per-run
# nondeterminism or a genuine divergence, and exits non-zero when any diverges.
homelab-factory-verify:
	@if [ -z '$(FACTORY_EVIDENCE)' ]; then \
		echo 'require FACTORY_EVIDENCE=<retained run evidence directory>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to validate retained evidence'; \
		$(PYTHON) homelab/vm/factory_verify.py '$(FACTORY_EVIDENCE)' \
			$(if $(FACTORY_RELEASES),--release-set '$(FACTORY_RELEASES)') \
			$(if $(FACTORY_COMPARE_EVIDENCE),--compare-with '$(FACTORY_COMPARE_EVIDENCE)') \
			--plan; \
	else \
		$(PYTHON) homelab/vm/factory_verify.py '$(FACTORY_EVIDENCE)' \
			$(if $(FACTORY_RELEASES),--release-set '$(FACTORY_RELEASES)') \
			$(if $(FACTORY_COMPARE_EVIDENCE),--compare-with '$(FACTORY_COMPARE_EVIDENCE)'); \
	fi

# Gate 4 (PXE authority boundary): render the read-only PXE authority verdict
# from a run's switch.jsonl. It never boots, connects, installs, or mutates any
# evidence. SWITCH names the switch evidence log (one or more may be given via
# the shell); TOPOLOGY optionally overrides the default factory fabric; AUDIT_JSON
# optionally persists the full result JSON outside the retained evidence. Exit
# status is 0 PASS, 1 FAIL, 3 NOT-PROVABLE.
homelab-pxe-authority-audit:
	@if [ -z '$(SWITCH)' ]; then \
		echo 'require SWITCH=<path to a run'\''s evidence switch.jsonl>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-pxe-authority-audit audit $(SWITCH) \
		$(if $(TOPOLOGY),--topology '$(TOPOLOGY)') \
		$(if $(AUDIT_JSON),--json '$(AUDIT_JSON)')

# Lifecycle recovery (gate 11): exercise controller restart/loss, PXE release
# rollback, failed-install recovery, broken-boot repair, directory/DNS loss,
# update-failure handling, workstation remint, and controller reconstruction.
# The loopback lab proves the release rollback, the ADR-0075 update gate, and
# the workstation remint for real; scenarios that need a live guest boot record
# their observable part and are marked NOT-RUN with a recorded reason. The dry
# run starts nothing; APPLY=1 writes the run bundle's evidence and result.json.
# A deferred proof is never promoted to a pass.
# Gate 12 (repeatability): run the complete sealed-input lifecycle at least
# twice from destroyed disposable state and compare the receipts. The dry run
# prints the phase plan, which producer measurements are available, and every
# precondition that would refuse. APPLY=1 runs the lifecycle REPEAT_ITERATIONS
# times, verifies each aggregate bundle, compares them, and exits non-zero on
# any divergence. It refuses to apply while the canonical Controller image is
# an empty never-installed disk -- run homelab-bootstrap-vm-install first.
homelab-factory-repeat:
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-factory-repeat \
			--evidence-root '$(REPEAT_EVIDENCE_ROOT)' \
			--work-root '$(REPEAT_WORK_ROOT)' \
			--iterations '$(REPEAT_ITERATIONS)' \
			--duration '$(FACTORY_DURATION)' \
			$(if $(FACTORY_RELEASES),--releases '$(FACTORY_RELEASES)') \
			$(if $(REPEAT_RECEIPT),--receipt '$(REPEAT_RECEIPT)'); \
	else \
		$(PYTHON) homelab/bin/homelab-factory-repeat \
			--evidence-root '$(REPEAT_EVIDENCE_ROOT)' \
			--work-root '$(REPEAT_WORK_ROOT)' \
			--iterations '$(REPEAT_ITERATIONS)' \
			--duration '$(FACTORY_DURATION)' \
			$(if $(FACTORY_RELEASES),--releases '$(FACTORY_RELEASES)') \
			$(if $(REPEAT_RECEIPT),--receipt '$(REPEAT_RECEIPT)') \
			--apply; \
	fi

homelab-factory-recover:
	@if [ -z '$(RECOVERY_RUN)' ]; then \
		echo 'require RECOVERY_RUN=<fresh run bundle directory>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to exercise recovery and judge'; \
		$(PYTHON) homelab/bin/homelab-lifecycle-recovery \
			--run '$(RECOVERY_RUN)' \
			$(if $(FACTORY_RELEASES),--releases '$(FACTORY_RELEASES)') \
			$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)') \
			$(if $(RECOVERY_BOOT),--boot) \
			$(if $(IDENTITY_BUNDLE),--identity-bundle '$(IDENTITY_BUNDLE)') \
			$(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') \
			--duration '$(FACTORY_DURATION)'; \
	else \
		$(PYTHON) homelab/bin/homelab-lifecycle-recovery \
			--run '$(RECOVERY_RUN)' \
			$(if $(FACTORY_RELEASES),--releases '$(FACTORY_RELEASES)') \
			$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)') \
			$(if $(RECOVERY_BOOT),--boot) \
			$(if $(IDENTITY_BUNDLE),--identity-bundle '$(IDENTITY_BUNDLE)') \
			$(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') \
			--duration '$(FACTORY_DURATION)' --apply; \
	fi

# Grade a produced recovery evidence stream fail-closed (read-only, no APPLY).
# A "partial" verdict is honest deferral, not a completed pass.
homelab-factory-recover-judge:
	@if [ -z '$(RECOVERY_EVIDENCE)' ]; then \
		echo 'require RECOVERY_EVIDENCE=<produced recovery-evidence.jsonl>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/workstations/lifecycle_recovery.py \
		'$(RECOVERY_EVIDENCE)'

homelab-bootstrap-seed:
	@$(PYTHON) homelab/seed/build.py \
		$(if $(SEED_OUTPUT),--output '$(SEED_OUTPUT)') \
		$(if $(SEED_PACKAGES),--packages '$(SEED_PACKAGES)')

# The bootstrap VM is isolated by construction. Planning is the default;
# create/run require APPLY=1, and destroy additionally requires the exact
# confirmation consumed by bootstrap_dc.py.
homelab-bootstrap-vm-plan:
	@$(PYTHON) homelab/vm/bootstrap_dc.py create

homelab-bootstrap-vm-status:
	@$(PYTHON) homelab/vm/bootstrap_dc.py status

homelab-bootstrap-vm-create:
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to create bootstrap-dc'; \
		$(PYTHON) homelab/vm/bootstrap_dc.py create; \
	else \
		$(PYTHON) homelab/vm/bootstrap_dc.py create --apply; \
	fi

homelab-bootstrap-vm-run: $(if $(strip $(ISO)),,homelab-media-arch)
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to run bootstrap-dc'; \
		$(PYTHON) homelab/vm/bootstrap_dc.py run \
			--iso '$(if $(ISO),$(ISO),$(ARCH_ISO))' \
			$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)'); \
	else \
		$(PYTHON) homelab/vm/bootstrap_dc.py run \
			--iso '$(if $(ISO),$(ISO),$(ARCH_ISO))' \
			$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)') --apply; \
	fi

homelab-bootstrap-vm-boot:
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to boot the installed disk'; \
		$(PYTHON) homelab/vm/bootstrap_dc.py run; \
	else \
		$(PYTHON) homelab/vm/bootstrap_dc.py run --apply; \
	fi

homelab-bootstrap-vm-destroy:
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'refusing destruction; require APPLY=1 CONFIRM=bootstrap-dc' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/vm/bootstrap_dc.py destroy --confirm '$(CONFIRM)'

# Install the canonical Controller image: the one step every live factory
# activity waits on, and until now a long manual console session. This boots
# the Arch ISO's kernel directly with console=ttyS0, so the manual `e` edit at
# the boot menu is gone, and answers the installer's prompts over the serial
# line the way the acceptance matrix already does (ADR 0058).
#
# Two answers are yours and are not automated away. CONFIRM carries the erasure
# phrase the installer asks you to type; the driver relays exactly those bytes
# and holds no copy of the phrase it could send on its own, so a person still
# answers the confirmation. The console password is read by getpass at your
# terminal and is never a Make variable, an environment variable, a file, or an
# argv element.
#
# Without APPLY=1 this is a dry run that prints the launch boundary and starts
# nothing. With APPLY=1 it refuses unless the manifest declares this exact disk
# serial and the image is still byte-identical to a newly created one, so it
# cannot be pointed at a Controller that already works.
homelab-bootstrap-vm-install: $(if $(strip $(ISO)),,homelab-media-arch)
	@if [ -z '$(SEED_ISO)' ]; then \
		echo 'require SEED_ISO=<the offline TELOS_SEED medium>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 and CONFIRM=<the erasure phrase the installer asks you to type> to install'; \
		$(PYTHON) homelab/vm/bootstrap_install.py \
			--iso '$(if $(ISO),$(ISO),$(ARCH_ISO))' \
			--seed-iso '$(SEED_ISO)'; \
	else \
		if [ -z '$(CONFIRM)' ]; then \
			echo 'refusing to erase the canonical image; require CONFIRM=<the erasure phrase the installer asks you to type>' >&2; \
			exit 2; \
		fi; \
		$(PYTHON) homelab/vm/bootstrap_install.py \
			--iso '$(if $(ISO),$(ISO),$(ARCH_ISO))' \
			--seed-iso '$(SEED_ISO)' \
			--confirm '$(CONFIRM)' --apply; \
	fi

# Physical attachment is a separate gate from VM creation and service
# convergence. NETWORK_CONFIG stays in the private overlay and must describe a
# tap and bridge that the operator created before running these targets.
homelab-bootstrap-network-preflight:
	@if [ -z '$(NETWORK_CONFIG)' ]; then \
		echo 'require NETWORK_CONFIG=<private 0600 attachment JSON>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/vm/bootstrap_dc.py run \
		--network-config '$(abspath $(NETWORK_CONFIG))'
	@printf '%s\n' \
		'Guest preflight, at the isolated serial console:' \
		'  sudo /usr/local/sbin/homelab-network-attach-preflight' \
		'  cat /proc/sys/kernel/random/boot_id' \
		"  sed -n 's/.*\"commit\": \"\\([0-9a-f]*\\)\".*/\\1/p' /opt/telos-source/seed-receipt.json" \
		'Do not attach unless it reports RESULT PASS; then power off.'

homelab-bootstrap-network-plan: homelab-bootstrap-network-preflight
	@printf '%s\n' \
		'Plan only: UniFi remains DHCP, DNS, and routing authority.' \
		'Time uses only the explicitly allowed external NTP path.' \
		'Record the fixed MAC from NETWORK_CONFIG in the UniFi reservation.' \
		'Confirm the selected switch port is an access port on the validation VLAN.' \
		'No DHCP options 66/67 and no controller authority services.' \
		'Next: make homelab-bootstrap-network-host-plan'

homelab-bootstrap-network-host-plan: homelab-bootstrap-network-preflight
	@sudo env TAP_OWNER="$$(id -un)" homelab/bin/homelab-host-network prepare

homelab-bootstrap-network-host-prepare: homelab-bootstrap-network-preflight
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1, then type the helper confirmation'; \
		sudo env TAP_OWNER="$$(id -un)" \
			homelab/bin/homelab-host-network prepare; \
	else \
		sudo env TAP_OWNER="$$(id -un)" APPLY=1 \
			homelab/bin/homelab-host-network prepare; \
	fi

homelab-bootstrap-network-receipt:
	@if [ -z '$(NETWORK_RECEIPT)' ] || [ -z '$(GUEST_BOOT_ID)' ] || \
	    [ -z '$(GUEST_SOURCE_COMMIT)' ]; then \
		echo 'require NETWORK_RECEIPT=<private path> GUEST_BOOT_ID=<UUID> GUEST_SOURCE_COMMIT=<full SHA>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/vm/preflight_receipt.py record \
		--output '$(abspath $(NETWORK_RECEIPT))' \
		--disk '$(abspath build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2)' \
		--serial TELOS-BOOTSTRAP-DC1 \
		--guest-boot-id '$(GUEST_BOOT_ID)' \
		--guest-source-commit '$(GUEST_SOURCE_COMMIT)' \
		--host-tool-commit "$$(git rev-parse HEAD)"

homelab-bootstrap-network-authorize:
	@if [ -z '$(NETWORK_RECEIPT)' ] || [ -z '$(CONFIRM)' ]; then \
		echo "require NETWORK_RECEIPT=<private path> CONFIRM='ATTACH <token>'" >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/vm/preflight_receipt.py authorize \
		--receipt '$(abspath $(NETWORK_RECEIPT))' --confirm '$(CONFIRM)'

homelab-bootstrap-network-run:
	@if [ -z '$(NETWORK_CONFIG)' ]; then \
		echo 'require NETWORK_CONFIG=<private 0600 attachment JSON>' >&2; exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: an applied launch also requires NETWORK_RECEIPT=<fresh authorized receipt>'; \
		$(PYTHON) homelab/vm/bootstrap_dc.py run \
			--network-config '$(abspath $(NETWORK_CONFIG))'; \
	else \
		if [ -z '$(NETWORK_RECEIPT)' ]; then \
			echo 'require NETWORK_RECEIPT=<fresh private 0600 receipt>' >&2; exit 2; \
		fi; \
		$(PYTHON) homelab/vm/bootstrap_dc.py run \
			--network-config '$(abspath $(NETWORK_CONFIG))' \
			--network-receipt '$(abspath $(NETWORK_RECEIPT))' \
			--confirm '$(CONFIRM)' --apply; \
	fi

homelab-bootstrap-network-check:
	@if [ -z '$(NETWORK_CONFIG)' ]; then \
		echo 'require NETWORK_CONFIG=<private 0600 attachment JSON>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/vm/bootstrap_dc.py run \
		--network-config '$(abspath $(NETWORK_CONFIG))'
	@printf '%s\n' \
		'Verify in the guest:' \
		'  ip -brief address; ip route; resolvectl status; timedatectl' \
		'  sudo /usr/local/sbin/homelab-network-attach-preflight' \
		'Verify in UniFi: reserved MAC/IP, one DHCP authority, no options 66/67.' \
		'Then power off the controller and prove an ordinary client is unaffected.'

homelab-bootstrap-network-teardown:
	@if [ '$(APPLY)' != 1 ]; then \
		printf '%s\n' \
			'dry run: power off bootstrap-dc before detaching its tap' \
			'repeat with APPLY=1, then type the helper confirmation'; \
		sudo homelab/bin/homelab-host-network teardown; \
	else \
		sudo env APPLY=1 homelab/bin/homelab-host-network teardown; \
	fi

# Entirely local simulation: no TAP, bridge, host route, or UniFi mutation.
homelab-sim-plan:
	@$(PYTHON) homelab/vm/simulated_topology.py

homelab-sim-run: homelab-sim-deps
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to run one isolated cycle'; \
		$(PYTHON) homelab/vm/simulated_topology.py; \
	else \
		$(PYTHON) homelab/vm/simulated_topology.py --apply; \
	fi

homelab-sim-check:
	@PYTHONPATH=. $(PYTHON) -m unittest discover -s homelab/tests -t . -v

homelab-sim-deps:
	@missing=0; \
	for tool in '$(PYTHON)' qemu-system-x86_64 qemu-img sfdisk mcopy; do \
		if ! command -v "$$tool" >/dev/null 2>&1; then \
			echo "missing simulation tool: $$tool" >&2; missing=1; \
		fi; \
	done; \
	test "$$missing" -eq 0

homelab-sim-repeat: homelab-sim-deps
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 SIM_CYCLES=<positive integer>'; \
		$(PYTHON) homelab/vm/simulated_topology.py; \
	else \
		case '$(SIM_CYCLES)' in \
			''|*[!0-9]*|0) echo 'SIM_CYCLES must be a positive integer' >&2; exit 2;; \
		esac; \
		cycle=1; while [ "$$cycle" -le '$(SIM_CYCLES)' ]; do \
			echo "isolated simulation cycle $$cycle/$(SIM_CYCLES)"; \
			$(PYTHON) homelab/vm/simulated_topology.py --apply; \
			cycle=$$((cycle + 1)); \
		done; \
	fi

homelab-sim-auto-plan:
	@$(PYTHON) homelab/vm/simulated_topology.py --automated

homelab-sim-auto-run: homelab-sim-deps
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to run one unattended isolated cycle'; \
		$(PYTHON) homelab/vm/simulated_topology.py --automated; \
	else \
		$(PYTHON) homelab/vm/simulated_topology.py --automated --apply; \
	fi

homelab-sim-auto-repeat: homelab-sim-deps
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 SIM_CYCLES=<positive integer>'; \
		$(PYTHON) homelab/vm/simulated_topology.py --automated; \
	else \
		case '$(SIM_CYCLES)' in \
			''|*[!0-9]*|0) echo 'SIM_CYCLES must be a positive integer' >&2; exit 2;; \
		esac; \
		cycle=1; while [ "$$cycle" -le '$(SIM_CYCLES)' ]; do \
			echo "unattended isolated simulation cycle $$cycle/$(SIM_CYCLES)"; \
			$(PYTHON) homelab/vm/simulated_topology.py --automated --apply; \
			cycle=$$((cycle + 1)); \
		done; \
	fi

# Bounded concurrent Controller/workstation factory skeleton. State is always
# disposable and its switch listens only on loopback.
homelab-factory-sim-plan:
	@$(PYTHON) homelab/vm/factory_runner.py --duration '$(FACTORY_DURATION)' --target '$(FACTORY_TARGET)' $(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') $(if $(WORKSTATION_ISO),--workstation-iso '$(WORKSTATION_ISO)') $(if $(FACTORY_RELEASES),--releases '$(FACTORY_RELEASES)')

homelab-factory-sim-run: homelab-sim-deps
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to run the bounded factory skeleton'; \
		$(PYTHON) homelab/vm/factory_runner.py --duration '$(FACTORY_DURATION)' --target '$(FACTORY_TARGET)' $(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') $(if $(WORKSTATION_ISO),--workstation-iso '$(WORKSTATION_ISO)') $(if $(FACTORY_RELEASES),--releases '$(FACTORY_RELEASES)'); \
	else \
		$(PYTHON) homelab/vm/factory_runner.py --duration '$(FACTORY_DURATION)' --target '$(FACTORY_TARGET)' $(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') $(if $(WORKSTATION_ISO),--workstation-iso '$(WORKSTATION_ISO)') $(if $(FACTORY_RELEASES),--releases '$(FACTORY_RELEASES)') --apply; \
	fi

# A persistent Controller instance: the one mode whose disk is meant to change.
# Its state directory is its own, its disk name is disjoint from the acceptance
# canonical's, it takes an exclusive lock so one directory can never be opened
# by two runs, and bootstrap_dc.py refuses outright to run persistently against
# the acceptance canonical (build/homelab/vm/bootstrap-dc) — an accidental
# persistent run there would provision a domain onto the disk gates 3, 8 and 12
# require to be freshly installed every time.
#
# The disposable path is untouched: nothing here runs unless PERSISTENT_DC names
# an instance, and no acceptance target references these.
homelab-factory-persistent-plan:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/vm/bootstrap_dc.py \
		$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
		persistent-up \
		--instance '$(PERSISTENT_DC)' \
		--persistent-root '$(PERSISTENT_DC_ROOT)' \
		$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)')

homelab-factory-persistent-status:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/vm/bootstrap_dc.py persistent-status \
		--instance '$(PERSISTENT_DC)' \
		--persistent-root '$(PERSISTENT_DC_ROOT)'

# Creates the instance from the canonical image when absent (read-only against
# the canonical, under the same strict fence the disposable path uses), then
# boots it in place. Bringing it up again later reuses the same domain SID,
# krbtgt, and accounts, which is the whole point of the mode.
homelab-factory-persistent-up:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to create and boot the persistent instance'; \
		$(PYTHON) homelab/vm/bootstrap_dc.py \
			$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
			persistent-up \
			--instance '$(PERSISTENT_DC)' \
			--persistent-root '$(PERSISTENT_DC_ROOT)' \
			$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)'); \
	else \
		$(PYTHON) homelab/vm/bootstrap_dc.py \
			$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
			persistent-up \
			--instance '$(PERSISTENT_DC)' \
			--persistent-root '$(PERSISTENT_DC_ROOT)' \
			$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)') \
			--apply; \
	fi

# Provision Active Directory into a persistent instance, in place. A bring-up
# alone leaves an installed Controller with no domain; this is the step that
# gives it one, and it is deliberately separate from -up because it is
# long-running, it reads credentials typed at your terminal, it builds and
# destroys a secret-bearing convergence CD, and it attaches a simulated peer.
#
# The durable ESP is never rewritten. The disposable acceptance path reaches a
# root shell by injecting an init=/bin/bash entry into a THROWAWAY ESP; doing
# that to a durable loader default would leave a permanent root shell one power
# cycle away. It is unnecessary here: the offline installer already asked you to
# type a local-rescue console password into this image, so convergence logs in
# normally and asks you for that password at this terminal. No harness-generated
# credential ever reaches durable state, and nothing is written to a file, a
# Make variable, an environment variable, or argv.
#
# It also leaves the domain Administrator ENABLED with the password you type,
# unlike a disposable run: a persistent directory whose only built-in
# administrator is disabled cannot create an account, join a machine, or rotate
# a credential.
homelab-factory-persistent-converge-plan:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/vm/bootstrap_dc.py \
		$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
		persistent-converge \
		$(if $(DIRECTORY_IDENTITY),--directory-identity '$(DIRECTORY_IDENTITY)') \
		--instance '$(PERSISTENT_DC)' \
		--persistent-root '$(PERSISTENT_DC_ROOT)' \
		$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)')

homelab-factory-persistent-converge:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to provision the directory; it will ask at this terminal for the local-rescue and Administrator passwords'; \
		$(PYTHON) homelab/vm/bootstrap_dc.py \
			$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
			persistent-converge \
			$(if $(DIRECTORY_IDENTITY),--directory-identity '$(DIRECTORY_IDENTITY)') \
			--instance '$(PERSISTENT_DC)' \
			--persistent-root '$(PERSISTENT_DC_ROOT)' \
			$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)'); \
	else \
		$(PYTHON) homelab/vm/bootstrap_dc.py \
			$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
			persistent-converge \
			$(if $(DIRECTORY_IDENTITY),--directory-identity '$(DIRECTORY_IDENTITY)') \
			--instance '$(PERSISTENT_DC)' \
			--persistent-root '$(PERSISTENT_DC_ROOT)' \
			$(if $(SEED_ISO),--seed-iso '$(SEED_ISO)') \
			$(if $(RECONVERGE),--reconverge) \
			$(if $(PERSISTENT_CONVERGE_TIMEOUT),--timeout '$(PERSISTENT_CONVERGE_TIMEOUT)') \
			--apply; \
	fi

# Stage the owner's DURABLE account roster into a persistent instance, over the
# serial console. Separate from -converge because the console is the only
# channel that reaches a SIMULATED persistent instance at all: that guest has
# one QEMU socket netdev to the userspace gateway, with no NAT and no route to
# the host LAN, so the host-side Ansible path
# (make homelab-bootstrap-controller INVENTORY=...) cannot reach it.
#
# It refuses the synthetic acceptance roster outright. The names come from the
# owner's gitignored overlay under homelab/instance/identity/, which must exist
# AND itself name every directory role: minting permanent student/operator SIDs
# because an overlay was missing, or was the inert template, or renamed only
# some roles, is exactly the failure this exists to prevent.
#
# One password per contract role is typed at your terminal. Nothing is read
# from a file, a Make variable, an environment variable or argv, and nothing is
# written to the instance marker, a log, or this transcript.
#
# The daily administrator is staged as a `standard` directory account and never
# joins Domain Admins: that separation is what gate 8's domain-admin-separate
# check proves, and it is not this target's to widen.
homelab-factory-persistent-accounts-plan:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/vm/bootstrap_dc.py \
		$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
		persistent-accounts \
		--instance '$(PERSISTENT_DC)' \
		--persistent-root '$(PERSISTENT_DC_ROOT)' \
		$(if $(IDENTITY_OVERLAY),--identity-overlay '$(IDENTITY_OVERLAY)') \
		$(if $(CHANGE_AT_FIRST_LOGON),--change-at-first-logon)

homelab-factory-persistent-accounts:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to stage the durable roster; it will ask at this terminal for the local-rescue password and one password per contract role'; \
		$(PYTHON) homelab/vm/bootstrap_dc.py \
			$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
			persistent-accounts \
			--instance '$(PERSISTENT_DC)' \
			--persistent-root '$(PERSISTENT_DC_ROOT)' \
			$(if $(IDENTITY_OVERLAY),--identity-overlay '$(IDENTITY_OVERLAY)') \
			$(if $(CHANGE_AT_FIRST_LOGON),--change-at-first-logon); \
	else \
		$(PYTHON) homelab/vm/bootstrap_dc.py \
			$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
			persistent-accounts \
			--instance '$(PERSISTENT_DC)' \
			--persistent-root '$(PERSISTENT_DC_ROOT)' \
			$(if $(IDENTITY_OVERLAY),--identity-overlay '$(IDENTITY_OVERLAY)') \
			$(if $(CHANGE_AT_FIRST_LOGON),--change-at-first-logon) \
			$(if $(RESTAGE),--restage) \
			$(if $(PERSISTENT_ACCOUNTS_TIMEOUT),--timeout '$(PERSISTENT_ACCOUNTS_TIMEOUT)') \
			--apply; \
	fi

# Probe one persistent instance on the PER-RUN loopback fabric, with no
# workstation (TASK-28, homelab/DURABLE-WORKSTATION-FLOW.md step 3). The dry run
# checks the binding -- realm, fabric addressing and roster fingerprint agree --
# and prints the plan; it starts nothing. APPLY=1 boots the instance's own disk
# in place on a per-run switch and gateway, logs in as local-rescue with the
# password typed once at this terminal, proves AD live, reads the realm and
# domain SID, checks the address, gateway, DNS records and clock, stages and
# destroys one tj- join principal, and powers the guest off over its console.
# Evidence (redacted transcript, switch.jsonl, result.json) is retained under
# the gitignored homelab/var/factory/persistent-probe/.
homelab-factory-persistent-probe:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo 'dry run: repeat with APPLY=1 to boot the instance on the per-run fabric; it will ask at this terminal for the local-rescue password'; \
		$(PYTHON) homelab/vm/persistent_controller_session.py \
			$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
			probe \
			--instance '$(PERSISTENT_DC)' \
			--persistent-root '$(PERSISTENT_DC_ROOT)' \
			$(if $(DIRECTORY_IDENTITY),--directory-identity '$(DIRECTORY_IDENTITY)') \
			$(if $(IDENTITY_OVERLAY),--identity-overlay '$(IDENTITY_OVERLAY)') \
			$(if $(REPAIR_SID),--repair-sid); \
	else \
		$(PYTHON) homelab/vm/persistent_controller_session.py \
			$(if $(FACTORY_CONTROLLER_STATE),--state-dir '$(FACTORY_CONTROLLER_STATE)') \
			probe \
			--instance '$(PERSISTENT_DC)' \
			--persistent-root '$(PERSISTENT_DC_ROOT)' \
			$(if $(DIRECTORY_IDENTITY),--directory-identity '$(DIRECTORY_IDENTITY)') \
			$(if $(IDENTITY_OVERLAY),--identity-overlay '$(IDENTITY_OVERLAY)') \
			$(if $(REPAIR_SID),--repair-sid) \
			--apply; \
	fi

# Disk-erasing: this deletes a real directory server, so it needs APPLY=1, the
# stable instance name, and the exact confirmation carrying that name.
homelab-factory-persistent-destroy:
	@if [ -z '$(PERSISTENT_DC)' ]; then \
		echo 'require PERSISTENT_DC=<instance name>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		echo "refusing destruction; require APPLY=1 PERSISTENT_DC=<instance> CONFIRM='DESTROY <instance>'" >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/vm/bootstrap_dc.py persistent-destroy \
		--instance '$(PERSISTENT_DC)' \
		--persistent-root '$(PERSISTENT_DC_ROOT)' \
		--confirm '$(CONFIRM)'

DURABLE_WS_REQUIRE = @if [ -z '$(WORKSTATION)' ]; then echo 'require WORKSTATION=<name>' >&2; exit 2; fi
DURABLE_WS = $(PYTHON) homelab/bin/homelab-durable-workstation --root '$(DURABLE_WORKSTATION_ROOT)'
DURABLE_WS_BIND = $(if $(WINDOWS_RUN),--windows-run '$(WINDOWS_RUN)') $(if $(PERSISTENT_DC),--persistent-dc '$(PERSISTENT_DC)') --persistent-root '$(PERSISTENT_DC_ROOT)'

# Read-only: what adopting WINDOWS_RUN into WORKSTATION would do.
homelab-durable-workstation-plan:
	$(DURABLE_WS_REQUIRE)
	@$(DURABLE_WS) plan --workstation '$(WORKSTATION)' $(DURABLE_WS_BIND)

homelab-durable-workstation-status:
	$(DURABLE_WS_REQUIRE)
	@$(DURABLE_WS) status --workstation '$(WORKSTATION)'

# Moves the gate-5 disk and its one-use publication into the kept workstation's
# custody; a dry run without APPLY=1.
homelab-durable-workstation-adopt:
	$(DURABLE_WS_REQUIRE)
	@if [ -z '$(WINDOWS_RUN)' ] || [ -z '$(PERSISTENT_DC)' ]; then echo 'require WINDOWS_RUN=<gate-5 bundle> PERSISTENT_DC=<instance>' >&2; exit 2; fi
	@$(DURABLE_WS) adopt --workstation '$(WORKSTATION)' $(DURABLE_WS_BIND) $(if $(filter 1,$(APPLY)),--apply)

# Shreds the publication first, then the disk; needs APPLY=1 and
# CONFIRM='DESTROY <name>', and lists the machine accounts left in the directory.
homelab-durable-workstation-destroy:
	$(DURABLE_WS_REQUIRE)
	@$(DURABLE_WS) destroy --workstation '$(WORKSTATION)' $(if $(filter 1,$(APPLY)),--apply --confirm '$(CONFIRM)')

homelab-windows-install-prepare:
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-windows-install-prepare; \
	else \
		$(PYTHON) homelab/bin/homelab-windows-install-prepare --apply; \
	fi

homelab-windows-install-run:
	@if [ -z '$(WINDOWS_RUN)' ]; then \
		echo 'require WINDOWS_RUN=<prepared private bundle>' >&2; exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-windows-install-run \
			--bundle '$(WINDOWS_RUN)' --duration '$(FACTORY_DURATION)'; \
	else \
		$(PYTHON) homelab/bin/homelab-windows-install-run \
			--bundle '$(WINDOWS_RUN)' --duration '$(FACTORY_DURATION)' --apply; \
	fi

# Arch-second install (gate 7): PXE-boot Arch against the persistent
# Windows disk and install into the free slot, preserving Windows. Prepare
# builds a disposable overlay bundle; run drives the install and validates
# preservation. Disposable, loopback-only; APPLY=1 mutates the overlay.
homelab-arch-install-prepare:
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-arch-install-prepare \
			$(if $(WINDOWS_RUN),--windows-disk '$(WINDOWS_RUN)'); \
	else \
		$(PYTHON) homelab/bin/homelab-arch-install-prepare \
			$(if $(WINDOWS_RUN),--windows-disk '$(WINDOWS_RUN)') --apply; \
	fi

homelab-arch-install-run:
	@if [ -z '$(ARCH_RUN)' ]; then \
		echo 'require ARCH_RUN=<prepared arch install bundle>' >&2; exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-arch-install-run \
			--bundle '$(ARCH_RUN)' --duration '$(FACTORY_DURATION)'; \
	else \
		$(PYTHON) homelab/bin/homelab-arch-install-run \
			--bundle '$(ARCH_RUN)' --duration '$(FACTORY_DURATION)' --apply; \
	fi

# Arch join and login (gate 8): drive a joined Arch guest through the SSSD
# identity lifecycle and emit the evidence the judge grades. Run drives the
# guest; judge grades a produced evidence file (read-only, no APPLY gate).
homelab-arch-identity-prepare:
	@if [ -z '$(ARCH_RUN)' ]; then \
		echo 'require ARCH_RUN=<passing arch install bundle>' >&2; exit 2; \
	fi
	@if [ -z '$(WINDOWS_IDENTITY_EVIDENCE)' ]; then \
		echo 'require WINDOWS_IDENTITY_EVIDENCE=<produced acceptance JSONL>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-arch-identity-prepare \
			--install-bundle '$(ARCH_RUN)' \
			--windows-evidence '$(WINDOWS_IDENTITY_EVIDENCE)'; \
	else \
		$(PYTHON) homelab/bin/homelab-arch-identity-prepare \
			--install-bundle '$(ARCH_RUN)' \
			--windows-evidence '$(WINDOWS_IDENTITY_EVIDENCE)' --apply; \
	fi

homelab-arch-identity-run:
	@if [ -z '$(ARCH_IDENTITY_BUNDLE)' ]; then \
		echo 'require ARCH_IDENTITY_BUNDLE=<joined arch bundle>' >&2; exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-arch-identity-run \
			--bundle '$(ARCH_IDENTITY_BUNDLE)' \
			--duration '$(FACTORY_DURATION)'; \
	else \
		$(PYTHON) homelab/bin/homelab-arch-identity-run \
			--bundle '$(ARCH_IDENTITY_BUNDLE)' \
			--duration '$(FACTORY_DURATION)' --apply; \
	fi

homelab-arch-identity-judge:
	@if [ -z '$(ARCH_IDENTITY_EVIDENCE)' ]; then \
		echo 'require ARCH_IDENTITY_EVIDENCE=<produced JSONL evidence>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-arch-identity-judge \
		'$(ARCH_IDENTITY_EVIDENCE)'

# Dual-boot acceptance (gate 10): from cold boot, prove the Windows-default
# five-second menu, Arch selectability, EFI recovery choices, and an
# unchanged GPT against a fresh overlay of the completed gate-7 disk.
# Disposable, disk-only (no PXE, no media); APPLY=1 mutates the overlay.
homelab-dualboot-acceptance-prepare:
	@if [ -z '$(GATE7_RUN)' ]; then \
		echo 'require GATE7_RUN=<completed gate-7 install bundle>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-dualboot-acceptance prepare \
			--gate7-bundle '$(GATE7_RUN)'; \
	else \
		$(PYTHON) homelab/bin/homelab-dualboot-acceptance prepare \
			--gate7-bundle '$(GATE7_RUN)' --apply; \
	fi

homelab-dualboot-acceptance-run:
	@if [ -z '$(DUALBOOT_RUN)' ]; then \
		echo 'require DUALBOOT_RUN=<prepared dual-boot bundle>' >&2; exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-dualboot-acceptance run \
			--bundle '$(DUALBOOT_RUN)' --duration '$(FACTORY_DURATION)'; \
	else \
		$(PYTHON) homelab/bin/homelab-dualboot-acceptance run \
			--bundle '$(DUALBOOT_RUN)' --duration '$(FACTORY_DURATION)' \
			--apply; \
	fi

homelab-dualboot-acceptance-judge:
	@if [ -z '$(DUALBOOT_EVIDENCE)' ]; then \
		echo 'require DUALBOOT_EVIDENCE=<produced JSONL evidence>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-dualboot-acceptance judge \
		'$(DUALBOOT_EVIDENCE)'

# Prove a completed image root against its role contract and the signed seed
# receipt that built it. Read-only: it audits the root without mounting,
# booting, or mutating anything, so it is safe before promotion.
homelab-image-promotion-gate:
	@if [ -z '$(IMAGE_ROOT)' ] || [ -z '$(IMAGE_RECEIPT)' ] \
			|| [ -z '$(IMAGE_PROFILE)' ]; then \
		echo 'require IMAGE_PROFILE=<installer-live|controller-seed|workstation-install>' >&2; \
		echo 'require IMAGE_ROOT=<candidate root> IMAGE_RECEIPT=<signed seed receipt>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-image-promotion-gate \
		--profile '$(IMAGE_PROFILE)' --root '$(IMAGE_ROOT)' \
		--receipt '$(IMAGE_RECEIPT)' \
		$(if $(IMAGE_EVIDENCE),--evidence '$(IMAGE_EVIDENCE)')

# Grade a booted candidate image's declared systemd services against the
# tracked contract, from the transcript the live capture step retained. Pure
# host-side: no guest, no root, no QEMU, and no registry override -- the
# tracked contract is the only contract a verdict may rest on.
homelab-image-service-gate:
	@if [ -z '$(IMAGE_TRANSCRIPT)' ] || [ -z '$(IMAGE_PROFILE)' ]; then \
		echo 'require IMAGE_PROFILE=<installer-live|controller-seed|workstation-install>' >&2; \
		echo 'require IMAGE_TRANSCRIPT=<retained guest console capture>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-image-service-gate \
		--profile '$(IMAGE_PROFILE)' \
		$(if $(IMAGE_SERVICE_TOKEN),--token '$(IMAGE_SERVICE_TOKEN)') \
		$(if $(IMAGE_SERVICE_EVIDENCE),--evidence '$(IMAGE_SERVICE_EVIDENCE)') \
		'$(IMAGE_TRANSCRIPT)'

homelab-windows-identity-judge:
	@if [ -z '$(WINDOWS_IDENTITY_EVIDENCE)' ]; then \
		echo 'require WINDOWS_IDENTITY_EVIDENCE=<private JSONL evidence>' >&2; \
		exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-windows-identity-judge \
		'$(WINDOWS_IDENTITY_EVIDENCE)'

homelab-windows-identity-prepare:
	@if [ -z '$(WINDOWS_RUN)' ]; then \
		echo 'require WINDOWS_RUN=<retained private Windows bundle>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-windows-identity-prepare \
			--bundle '$(WINDOWS_RUN)' $(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') $(if $(WINDOWS_SUBMIT_FOCUS_TABS),--calibrate-submit-focus-tabs '$(WINDOWS_SUBMIT_FOCUS_TABS)') $(if $(WINDOWS_REVIEWED_SUBMIT_FOCUS),--authorize-reviewed-submit-focus); \
	else \
		$(PYTHON) homelab/bin/homelab-windows-identity-prepare \
			--bundle '$(WINDOWS_RUN)' $(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') $(if $(WINDOWS_SUBMIT_FOCUS_TABS),--calibrate-submit-focus-tabs '$(WINDOWS_SUBMIT_FOCUS_TABS)') $(if $(WINDOWS_REVIEWED_SUBMIT_FOCUS),--authorize-reviewed-submit-focus) --apply; \
	fi

homelab-windows-identity-run:
	@if [ -z '$(WINDOWS_IDENTITY_ATTEMPT)' ]; then \
		echo 'require WINDOWS_IDENTITY_ATTEMPT=<prepared private attempt>' >&2; \
		exit 2; \
	fi
	@if [ '$(APPLY)' != 1 ]; then \
		$(PYTHON) homelab/bin/homelab-windows-identity-run \
			--attempt '$(WINDOWS_IDENTITY_ATTEMPT)' $(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') $(if $(WINDOWS_SUBMIT_FOCUS_TABS),--calibrate-submit-focus-tabs '$(WINDOWS_SUBMIT_FOCUS_TABS)') $(if $(WINDOWS_REVIEWED_SUBMIT_FOCUS),--authorize-reviewed-submit-focus); \
	else \
		$(PYTHON) homelab/bin/homelab-windows-identity-run \
			--attempt '$(WINDOWS_IDENTITY_ATTEMPT)' \
			$(if $(FACTORY_CONTROLLER_STATE),--controller-state '$(FACTORY_CONTROLLER_STATE)') \
			$(if $(WINDOWS_SUBMIT_FOCUS_TABS),--calibrate-submit-focus-tabs '$(WINDOWS_SUBMIT_FOCUS_TABS)') \
			$(if $(WINDOWS_REVIEWED_SUBMIT_FOCUS),--authorize-reviewed-submit-focus) \
			--apply; \
	fi

# Converge only the temporary Controller role. The private inventory supplies
# every identity value and the opt-in provisioning secret path. Check mode is
# the default; APPLY=1 is required to mutate the guest.
homelab-bootstrap-controller:
	@if [ -z '$(INVENTORY)' ]; then \
		echo 'require INVENTORY=<private Ansible inventory>' >&2; exit 2; \
	fi
	@if [ '$(APPLY)' = 1 ]; then \
		cd homelab/ansible && ansible-playbook -i '$(abspath $(INVENTORY))' \
			playbooks/bootstrap-controller.yml; \
	else \
		cd homelab/ansible && ansible-playbook -i '$(abspath $(INVENTORY))' \
			playbooks/bootstrap-controller.yml --check --diff; \
	fi

# Each PXE target is built independently from operator-supplied media.
# VERSION uses the publication form YYYYMMDD.NNN.
homelab-pxe-controller:
	@if [ -z '$(SOURCE)' ] || [ -z '$(VERSION)' ] || [ -z '$(BASE_URL)' ]; then \
		echo 'require SOURCE=<controller tree> VERSION=YYYYMMDD.NNN BASE_URL=<immutable URL>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/pxe/targets/controller.py build \
		--source '$(SOURCE)' --releases homelab/var/pxe \
		--version '$(VERSION)' --base-url '$(BASE_URL)'

homelab-pxe-arch:
	@if [ -z '$(SOURCE)' ] || [ -z '$(VERSION)' ] || [ -z '$(BASE_URL)' ]; then \
		echo 'require SOURCE=<mounted Arch ISO> VERSION=YYYYMMDD.NNN BASE_URL=<immutable URL>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/pxe/arch-workstation stage \
		--source '$(SOURCE)' --releases homelab/var/pxe \
		--version '$(VERSION)' --base-url '$(BASE_URL)'

homelab-pxe-windows:
	@if [ -z '$(ISO)' ] || [ -z '$(WIMBOOT)' ] || [ -z '$(VERSION)' ]; then \
		echo 'require ISO=<Windows 11 ISO> WIMBOOT=<wimboot binary> VERSION=YYYYMMDD.NNN' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/pxe/windows/stage.py \
		--iso '$(ISO)' --wimboot '$(WIMBOOT)' \
		--output homelab/var/pxe/windows --release '$(VERSION)' \
		$(if $(BASE_URL),--base-url '$(BASE_URL)',)

homelab-pxe-all:
	@$(MAKE) --no-print-directory homelab-pxe-controller \
		SOURCE='$(CONTROLLER_SOURCE)' VERSION='$(VERSION)' BASE_URL='$(CONTROLLER_BASE_URL)'
	@$(MAKE) --no-print-directory homelab-pxe-arch \
		SOURCE='$(ARCH_SOURCE)' VERSION='$(VERSION)' BASE_URL='$(ARCH_BASE_URL)'
	@$(MAKE) --no-print-directory homelab-pxe-windows \
		ISO='$(WINDOWS_ISO)' WIMBOOT='$(WIMBOOT)' VERSION='$(VERSION)' \
		BASE_URL='$(WINDOWS_BASE_URL)'

homelab-pxe-release-set:
	@if [ -z '$(VERSION)' ] || [ -z '$(CONTROLLER_SOURCE)' ] || [ -z '$(BASE_URL)' ]; then \
		echo 'require VERSION=YYYYMMDD.NNN CONTROLLER_SOURCE=<mkarchiso netboot tree> BASE_URL=<immutable root URL>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-pxe-release-set build \
		--releases homelab/var/pxe --version '$(VERSION)' \
		--controller-source '$(CONTROLLER_SOURCE)' \
		$(if $(strip $(ARCH_SOURCE)),--arch-source '$(ARCH_SOURCE)',--arch-cache '$(FACTORY_ARCH_SOURCE_CACHE)') \
		--base-url '$(BASE_URL)' --seal '$(FACTORY_MEDIA_SEAL)' \
		--arch-iso '$(ARCH_ISO)' --arch-receipt '$(ARCH_ISO).receipt.json' \
		--windows-iso '$(WINDOWS_ISO_CACHE)' \
		--windows-provenance '$(WINDOWS_ISO_CACHE).provenance.json' \
		--windows-verification '$(WINDOWS_ISO_CACHE).verification.json' \
		--windows-install-source '$(WINDOWS_INSTALL_SOURCE)' \
		--wimboot '$(WIMBOOT)' --wimboot-metadata homelab/media/wimboot.json

homelab-pxe-release-set-verify:
	@if [ -z '$(RELEASE_SET)' ]; then \
		echo 'require RELEASE_SET=<versioned release-set directory>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-pxe-release-set verify \
		'$(RELEASE_SET)' --seal '$(FACTORY_MEDIA_SEAL)'

homelab-pxe-release-set-rollback:
	@if [ -z '$(VERSION)' ]; then \
		echo 'require VERSION=YYYYMMDD.NNN' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-pxe-release-set select \
		--releases homelab/var/pxe --version '$(VERSION)'

homelab-pxe-test:
	@$(PYTHON) -m unittest \
		homelab.tests.test_pxe_release \
		homelab.tests.test_pxe_release_set \
		homelab.tests.test_pxe_controller_target \
		homelab.tests.test_arch_workstation_pxe \
		homelab.tests.test_windows_pxe \
		homelab.tests.test_pxe_deploy -v

homelab-pxe-verify:
	@if [ -z '$(RELEASE)' ]; then \
		echo 'require RELEASE=<versioned release directory>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-pxe-release verify '$(RELEASE)'

homelab-pxe-publish:
	@if [ -z '$(RELEASE)' ] || [ -z '$(DESTINATION)' ]; then \
		echo 'require RELEASE=<local release> DESTINATION=<host:/absolute/root>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-pxe-deploy publish \
		'$(RELEASE)' '$(DESTINATION)' $(if $(filter 1,$(APPLY)),--apply,)

homelab-pxe-rollback:
	@if [ -z '$(TARGET)' ] || [ -z '$(VERSION)' ] || [ -z '$(DESTINATION)' ]; then \
		echo 'require TARGET=<controller|arch-workstation|windows> VERSION=YYYYMMDD.NNN DESTINATION=<host:/absolute/root>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/bin/homelab-pxe-deploy rollback \
		'$(TARGET)' '$(VERSION)' '$(DESTINATION)' \
		$(if $(filter 1,$(APPLY)),--apply,)

homelab-workstation-plan:
	@if [ -z '$(DISK_BYTES)' ]; then \
		echo 'require DISK_BYTES=<exact integer byte count>' >&2; exit 2; \
	fi
	@PYTHONPATH=. $(PYTHON) homelab/workstations/layout.py \
		--disk-bytes '$(DISK_BYTES)' \
		--profile '$(or $(LAYOUT_PROFILE),$(PROFILE),homelab/workstations/profiles/default-layout.json)' \
		--workstation-profile '$(or $(WORKSTATION_PROFILE),homelab/workstations/profiles/phase1-windows-primary.json)' \
		$(if $(RECORD),--record '$(RECORD)',)

homelab-workstation-verify:
	@if [ -z '$(INSTANCE)' ]; then \
		echo 'require INSTANCE=<private acceptance-instance JSON>' >&2; exit 2; \
	fi
	@$(PYTHON) homelab/workstations/acceptance.py --instance '$(INSTANCE)' validate

homelab-arch-update-check:
	@rc=0; $(PYTHON) homelab/updates/arch_policy.py || rc=$$?; \
		test "$$rc" -eq 0 -o "$$rc" -eq 75

homelab-arch-update-test:
	@$(PYTHON) -m unittest homelab.tests.test_arch_updates -v

homelab-private-bootstrap:
	@$(PYTHON) scripts/telos-private bootstrap --git-init

homelab-private-onboard:
	@$(PYTHON) scripts/telos-private onboard --git-init

homelab-private-check:
	@if [ -z '$(IDENTIFIERS)' ]; then \
		echo 'require IDENTIFIERS=<private denylist file>' >&2; exit 2; \
	fi
	@$(PYTHON) scripts/telos-private check-public --identifiers '$(IDENTIFIERS)'

# Seed the private instance overlay from the tracked template. Never overwrites:
# the overlay is not in Git, so clobbering it loses the only copy.
# Seed only the template paths that are actually missing. The old form tested
# the top-level directory and nothing else, so a checkout that already had
# homelab/instance/ but not, say, homelab/instance/identity/ was told
# "leaving it alone" and silently got nothing -- which is this checkout's real
# state, and left the roster with no principals file to read. An existing file
# is never overwritten: local answers and inventories are the operator's.
homelab-instance:
	@seeded=$$(find homelab/instance-example -type f -printf '%P\n' | sort | \
		while read -r item; do \
			if [ ! -e "homelab/instance/$$item" ]; then \
				mkdir -p "homelab/instance/$$(dirname "$$item")"; \
				cp "homelab/instance-example/$$item" "homelab/instance/$$item"; \
				printf '  %s\n' "$$item"; \
			fi; \
		done); \
	if [ -z "$$seeded" ]; then \
		echo "homelab/instance already holds every template path; nothing was changed"; \
	else \
		echo "seeded these missing paths from homelab/instance-example:"; \
		printf '%s\n' "$$seeded"; \
		echo "fill in their placeholders before using them"; \
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
		'make check      Site manifest, tests, and the tmt registry gate' \
		'make homelab-test         Run the homelab suite verbosely' \
		'make homelab-check        Fast honest verification for homelab edits' \
		'make homelab-lab          Report whether the QEMU lab can run' \
		'make homelab-media        Fresh-fetch official disposable media' \
		'make homelab-media-workstation-repo  Acquire the offline workstation pacman repo' \
		'make homelab-bootstrap-seed  Build the isolated Controller seed ISO' \
		'make homelab-bootstrap-vm-boot  Boot the installed Controller disk' \
		'make homelab-bootstrap-network-plan NETWORK_CONFIG=<private JSON>' \
		'                         Plan the controlled physical attachment' \
		'make homelab-sim-plan    Plan without changing local state' \
		'make homelab-sim-run APPLY=1  Run one isolated cycle' \
		'make homelab-sim-auto-run APPLY=1  Run one unattended cycle' \
		'make homelab-sim-auto-repeat APPLY=1 SIM_CYCLES=2' \
		'make homelab-sim-check   Run simulation acceptance tests' \
		'make homelab-sim-repeat APPLY=1 SIM_CYCLES=2' \
		'make homelab-factory-sim-plan  Plan the bounded factory skeleton' \
		'make homelab-factory-sim-run APPLY=1 FACTORY_DURATION=120' \
		'make homelab-factory-persistent-plan PERSISTENT_DC=<name>' \
		'                         Plan a persistent Controller instance' \
		'make homelab-factory-persistent-up APPLY=1 PERSISTENT_DC=<name>' \
		'                         Create when absent, then boot it in place' \
		'make homelab-factory-persistent-converge-plan PERSISTENT_DC=<name>' \
		'                         Plan provisioning a directory into it' \
		'make homelab-factory-persistent-converge APPLY=1 PERSISTENT_DC=<name>' \
		'                         Provision AD in place; asks for passwords' \
		'make homelab-factory-persistent-accounts-plan PERSISTENT_DC=<name>' \
		'                         Plan the durable account roster for an instance' \
		'make homelab-factory-persistent-accounts APPLY=1 PERSISTENT_DC=<name>' \
		'                         Stage the durable roster over the serial console' \
		'make homelab-factory-persistent-status PERSISTENT_DC=<name>' \
		"make homelab-factory-persistent-destroy APPLY=1 PERSISTENT_DC=<name> CONFIRM='DESTROY <name>'" \
		'make homelab-durable-workstation-plan WORKSTATION=<name> [WINDOWS_RUN=<bundle> PERSISTENT_DC=<name>]' \
		'make homelab-durable-workstation-adopt APPLY=1 WORKSTATION=<name> WINDOWS_RUN=<bundle> PERSISTENT_DC=<name>' \
		'                         Take custody of a gate-5 disk as a kept workstation' \
		'make homelab-durable-workstation-status WORKSTATION=<name>' \
		"make homelab-durable-workstation-destroy APPLY=1 WORKSTATION=<name> CONFIRM='DESTROY <name>'" \
		'make homelab-private-onboard  Build a sibling private overlay' \
		'make adr-digest           Regenerate the printable decision record' \
		'make clean      Remove build/ except durable VM state (build/homelab/vm)' \
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

# $(BUILD_ROOT)/homelab/vm is durable VM state, not build output: the canonical
# Controller image, persistent directory instances (whose domain cannot be
# rebuilt) and kept workstations. Each has its own CONFIRM-gated destroy target,
# so clean removes everything else and never that tree.
clean:
	@if [ -d '$(BUILD_ROOT)' ]; then \
		find '$(BUILD_ROOT)' -mindepth 1 -maxdepth 1 ! -name homelab -exec rm -rf {} +; \
		if [ -d '$(BUILD_ROOT)/homelab' ]; then \
			find '$(BUILD_ROOT)/homelab' -mindepth 1 -maxdepth 1 ! -name vm -exec rm -rf {} +; \
		fi; \
	fi
	@if [ -d '$(BUILD_ROOT)/homelab/vm' ]; then \
		echo 'kept $(BUILD_ROOT)/homelab/vm: durable VM state goes only through its own destroy targets'; \
	fi

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
