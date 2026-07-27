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
	dnsmasq nginx ipxe qemu-base edk2-ovmf ansible samba krb5 ntp \
	python-cryptography python-dnspython python-pexpect openresolv bind \
	openssh rsync gnupg fakeroot \
	wimlib libisoburn
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
WIMBOOT ?= homelab/var/media/wimboot

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
	homelab-converge-check homelab-bootstrap-deps \
	homelab-media homelab-media-arch homelab-media-windows \
	homelab-media-wimboot homelab-bootstrap-seed \
	homelab-bootstrap-vm-plan homelab-bootstrap-vm-status \
	homelab-bootstrap-vm-create homelab-bootstrap-vm-run \
	homelab-bootstrap-vm-boot homelab-bootstrap-vm-destroy \
	homelab-bootstrap-network-preflight homelab-bootstrap-network-plan \
	homelab-bootstrap-network-host-plan homelab-bootstrap-network-host-prepare \
	homelab-bootstrap-network-receipt homelab-bootstrap-network-authorize \
	homelab-bootstrap-network-run homelab-bootstrap-network-check \
	homelab-bootstrap-network-teardown \
	homelab-bootstrap-controller \
	homelab-pxe-controller homelab-pxe-arch homelab-pxe-windows \
	homelab-pxe-all homelab-pxe-test homelab-pxe-verify \
	homelab-pxe-publish homelab-pxe-rollback \
	homelab-workstation-plan homelab-workstation-verify \
	homelab-arch-update-check homelab-arch-update-test \
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

# Install the complete Arch build-host dependency set. This is an explicit
# alias so the workstation manual can name the phase it prepares.
homelab-bootstrap-deps: install-dependencies-arch

# Resolve current upstream media into an ignored cache. Arch is checked against
# its official digest and pinned release key. wimboot is version/hash pinned.
# Microsoft requires an interactive consumer-media link, so the aggregate
# target stops at that explicit gate until the operator supplies its ISO and
# the digest printed by Microsoft's verification table.
homelab-media: homelab-media-arch homelab-media-wimboot homelab-media-windows

homelab-media-arch:
	@homelab/media/fetch-arch

homelab-media-windows:
	@if [ -z '$(WINDOWS_ISO)' ] || [ -z '$(WINDOWS_SHA256)' ]; then \
		homelab/bin/homelab-fetch-windows --output '$(WINDOWS_ISO_CACHE)'; \
	else \
		homelab/bin/homelab-fetch-windows \
			--source '$(WINDOWS_ISO)' --expected-sha256 '$(WINDOWS_SHA256)' \
			--output '$(WINDOWS_ISO_CACHE)'; \
	fi

homelab-media-wimboot:
	@homelab/bin/homelab-fetch-wimboot --output '$(WIMBOOT)'

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

homelab-pxe-test:
	@cd homelab && $(PYTHON) -m unittest \
		tests.test_pxe_release tests.test_pxe_controller_target \
		tests.test_arch_workstation_pxe tests.test_windows_pxe \
		tests.test_pxe_deploy -v

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
	@cd homelab && $(PYTHON) -m unittest tests.test_arch_updates -v

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
		'make homelab-media        Fresh-fetch official disposable media' \
		'make homelab-bootstrap-seed  Build the isolated Controller seed ISO' \
		'make homelab-bootstrap-vm-boot  Boot the installed Controller disk' \
		'make homelab-bootstrap-network-plan NETWORK_CONFIG=<private JSON>' \
		'                         Plan the controlled physical attachment' \
		'make homelab-private-onboard  Build a sibling private overlay' \
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
