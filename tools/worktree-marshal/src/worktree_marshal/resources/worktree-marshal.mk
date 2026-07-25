# Worktree Marshal Make-fragment API 1. The command owns lifecycle validation
# and state; this file provides only a bounded, project-friendly interface.
ifndef WORKTREE_MARSHAL_MAKE_FRAGMENT_INCLUDED
WORKTREE_MARSHAL_MAKE_FRAGMENT_INCLUDED := 1

# Preserve an established project default. If the include appears before any
# project target, clear the temporary default selected by this fragment after
# its rules so GNU Make will select the first later project target normally.
override _WORKTREE_MARSHAL_PRIOR_DEFAULT_GOAL := $(.DEFAULT_GOAL)

WORKTREE_MARSHAL ?= worktree-marshal
WORKTREE_MARSHAL_DISPLAY_NAME ?= Worktree Marshal

# The native CLI requires an explicit immutable lifecycle profile.  Keep this
# as a trusted fixed word list so generated fragments can pin a different
# profile without allowing invocation-controlled shell input.  Compatibility
# launchers whose own argv selects a profile deliberately override it empty.
WORKTREE_MARSHAL_GLOBAL_ARGUMENTS ?= --profile generic-v1

WORKTREE_MARSHAL_RUN_TARGET ?= codex
WORKTREE_MARSHAL_STATUS_TARGET ?= status
WORKTREE_MARSHAL_REOPEN_TARGET ?= reopen
WORKTREE_MARSHAL_DIFF_TARGET ?= final-diff
WORKTREE_MARSHAL_INTEGRATE_TARGET ?= integrate
WORKTREE_MARSHAL_RESOLVE_TARGET ?= resolve
WORKTREE_MARSHAL_CONTINUE_TARGET ?= continue
WORKTREE_MARSHAL_ABORT_TARGET ?= abort
WORKTREE_MARSHAL_CLEAN_TARGET ?= clean-run
WORKTREE_MARSHAL_POSITIONAL_RUN_ID_COMPAT ?= 0

# These are trusted shell word lists supplied by the including Makefile, never
# data forwarded from a caller. The validated run ID is appended separately.
WORKTREE_MARSHAL_RUN_ARGUMENTS ?= run --agent codex
WORKTREE_MARSHAL_STATUS_ARGUMENTS ?= status
WORKTREE_MARSHAL_REOPEN_ARGUMENTS ?= reopen
WORKTREE_MARSHAL_DIFF_ARGUMENTS ?= final-diff
WORKTREE_MARSHAL_INTEGRATE_ARGUMENTS ?= integrate
WORKTREE_MARSHAL_RESOLVE_ARGUMENTS ?= resolve
WORKTREE_MARSHAL_CONTINUE_ARGUMENTS ?= continue
WORKTREE_MARSHAL_ABORT_ARGUMENTS ?= abort
WORKTREE_MARSHAL_CLEAN_ARGUMENTS ?= clean

override _WORKTREE_MARSHAL_CONFIGURATION_VARIABLES := \
	WORKTREE_MARSHAL \
	WORKTREE_MARSHAL_DISPLAY_NAME \
	WORKTREE_MARSHAL_GLOBAL_ARGUMENTS \
	WORKTREE_MARSHAL_RUN_TARGET \
	WORKTREE_MARSHAL_STATUS_TARGET \
	WORKTREE_MARSHAL_REOPEN_TARGET \
	WORKTREE_MARSHAL_DIFF_TARGET \
	WORKTREE_MARSHAL_INTEGRATE_TARGET \
	WORKTREE_MARSHAL_RESOLVE_TARGET \
	WORKTREE_MARSHAL_CONTINUE_TARGET \
	WORKTREE_MARSHAL_ABORT_TARGET \
	WORKTREE_MARSHAL_CLEAN_TARGET \
	WORKTREE_MARSHAL_POSITIONAL_RUN_ID_COMPAT \
	WORKTREE_MARSHAL_RUN_ARGUMENTS \
	WORKTREE_MARSHAL_STATUS_ARGUMENTS \
	WORKTREE_MARSHAL_REOPEN_ARGUMENTS \
	WORKTREE_MARSHAL_DIFF_ARGUMENTS \
	WORKTREE_MARSHAL_INTEGRATE_ARGUMENTS \
	WORKTREE_MARSHAL_RESOLVE_ARGUMENTS \
	WORKTREE_MARSHAL_CONTINUE_ARGUMENTS \
	WORKTREE_MARSHAL_ABORT_ARGUMENTS \
	WORKTREE_MARSHAL_CLEAN_ARGUMENTS

# Configuration is trusted Makefile code. Refuse environment and command-line
# replacement so a lifecycle invocation cannot turn these values into shell
# input. An including Makefile may use either an ordinary or override assignment.
$(foreach variable,$(_WORKTREE_MARSHAL_CONFIGURATION_VARIABLES),\
	$(if $(findstring command line,$(origin $(variable))),\
		$(error $(variable) must be configured in a Makefile),)\
	$(if $(findstring environment,$(origin $(variable))),\
		$(error $(variable) must be configured in a Makefile),))

override _WORKTREE_MARSHAL_TARGET_VARIABLES := \
	WORKTREE_MARSHAL_RUN_TARGET \
	WORKTREE_MARSHAL_STATUS_TARGET \
	WORKTREE_MARSHAL_REOPEN_TARGET \
	WORKTREE_MARSHAL_DIFF_TARGET \
	WORKTREE_MARSHAL_INTEGRATE_TARGET \
	WORKTREE_MARSHAL_RESOLVE_TARGET \
	WORKTREE_MARSHAL_CONTINUE_TARGET \
	WORKTREE_MARSHAL_ABORT_TARGET \
	WORKTREE_MARSHAL_CLEAN_TARGET

override _WORKTREE_MARSHAL_ALLOWED_TARGET_CHARACTERS := \
	0 1 2 3 4 5 6 7 8 9 \
	a b c d e f g h i j k l m n o p q r s t u v w x y z \
	A B C D E F G H I J K L M N O P Q R S T U V W X Y Z \
	. _ -
override _worktree_marshal_strip_characters = $(if $(strip $(1)),$(call _worktree_marshal_strip_characters,$(wordlist 2,999,$(1)),$(subst $(firstword $(1)),,$(2))),$(2))

$(foreach variable,$(_WORKTREE_MARSHAL_TARGET_VARIABLES),\
	$(if $(filter 1,$(words $($(variable)))),,\
		$(error $(WORKTREE_MARSHAL_DISPLAY_NAME) target names must each be one nonempty word))\
	$(if $(strip $(call _worktree_marshal_strip_characters,$(_WORKTREE_MARSHAL_ALLOWED_TARGET_CHARACTERS),$(value $(variable)))),\
		$(error $(WORKTREE_MARSHAL_DISPLAY_NAME) target names must match [A-Za-z0-9][A-Za-z0-9_.-]*),)\
	$(if $(filter .% -% _%,$($(variable))),\
		$(error $(WORKTREE_MARSHAL_DISPLAY_NAME) target names must match [A-Za-z0-9][A-Za-z0-9_.-]*),))

override _WORKTREE_MARSHAL_REQUIRED_TARGETS := \
	$(WORKTREE_MARSHAL_REOPEN_TARGET) \
	$(WORKTREE_MARSHAL_DIFF_TARGET) \
	$(WORKTREE_MARSHAL_INTEGRATE_TARGET) \
	$(WORKTREE_MARSHAL_RESOLVE_TARGET) \
	$(WORKTREE_MARSHAL_CONTINUE_TARGET) \
	$(WORKTREE_MARSHAL_ABORT_TARGET) \
	$(WORKTREE_MARSHAL_CLEAN_TARGET)
override _WORKTREE_MARSHAL_ALL_TARGETS := \
	$(WORKTREE_MARSHAL_RUN_TARGET) \
	$(WORKTREE_MARSHAL_STATUS_TARGET) \
	$(_WORKTREE_MARSHAL_REQUIRED_TARGETS)

ifneq ($(words $(_WORKTREE_MARSHAL_ALL_TARGETS)),9)
$(error $(WORKTREE_MARSHAL_DISPLAY_NAME) requires nine target names)
endif
ifneq ($(words $(sort $(_WORKTREE_MARSHAL_ALL_TARGETS))),9)
$(error $(WORKTREE_MARSHAL_DISPLAY_NAME) target names must be distinct)
endif
ifeq ($(strip $(WORKTREE_MARSHAL)),)
$(error $(WORKTREE_MARSHAL_DISPLAY_NAME) executable must not be empty)
endif
ifneq ($(filter 0 1,$(WORKTREE_MARSHAL_POSITIONAL_RUN_ID_COMPAT)),$(WORKTREE_MARSHAL_POSITIONAL_RUN_ID_COMPAT))
$(error WORKTREE_MARSHAL_POSITIONAL_RUN_ID_COMPAT must be 0 or 1)
endif

# MAKECMDGOALS is meaningful only for this Make process. Refuse attempts to
# spoof it and do not leak it into recursive project builds.
ifeq ($(filter undefined default,$(origin MAKECMDGOALS)),)
$(error MAKECMDGOALS may not be overridden)
endif
unexport MAKECMDGOALS

# For the ordinary recursive RUN=<value> form, capture the literal value without
# re-expanding nested Make syntax. GNU Make evaluates other assignment operators
# before reading this file; never forward arbitrary Make arguments. The optional
# positional form exists only for a compatibility migration. The pure-Make check
# admits YYYYMMDDtHHMMSSz- followed by 12 lowercase hexadecimal characters.
override _WORKTREE_MARSHAL_REQUESTED_TARGETS := $(filter $(_WORKTREE_MARSHAL_ALL_TARGETS),$(MAKECMDGOALS))
override _WORKTREE_MARSHAL_POSITIONAL_RUN_ID := $(strip \
	$(if $(filter 1,$(WORKTREE_MARSHAL_POSITIONAL_RUN_ID_COMPAT)),\
		$(if $(filter undefined,$(origin RUN)),\
			$(if $(filter 2,$(words $(MAKECMDGOALS))),\
				$(if $(filter $(firstword $(MAKECMDGOALS)),$(WORKTREE_MARSHAL_STATUS_TARGET) $(_WORKTREE_MARSHAL_REQUIRED_TARGETS)),\
					$(word 2,$(MAKECMDGOALS)))))))
override _WORKTREE_MARSHAL_RUN_ID := $(if $(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID),$(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID),$(value RUN))
override _worktree_marshal_strip_decimal = $(subst 9,,$(subst 8,,$(subst 7,,$(subst 6,,$(subst 5,,$(subst 4,,$(subst 3,,$(subst 2,,$(subst 1,,$(subst 0,,$(1)))))))))))
override _worktree_marshal_strip_hex = $(subst f,,$(subst e,,$(subst d,,$(subst c,,$(subst b,,$(subst a,,$(call _worktree_marshal_strip_decimal,$(1))))))))
override _worktree_marshal_hex_to_words = $(subst f,x ,$(subst e,x ,$(subst d,x ,$(subst c,x ,$(subst b,x ,$(subst a,x ,$(subst 9,x ,$(subst 8,x ,$(subst 7,x ,$(subst 6,x ,$(subst 5,x ,$(subst 4,x ,$(subst 3,x ,$(subst 2,x ,$(subst 1,x ,$(subst 0,x ,$(1)))))))))))))))))
override _worktree_marshal_character_count = $(words $(call _worktree_marshal_hex_to_words,$(1)))
override _WORKTREE_MARSHAL_RUN_DATE := $(word 1,$(subst t, ,$(_WORKTREE_MARSHAL_RUN_ID)))
override _WORKTREE_MARSHAL_RUN_AFTER_T := $(word 2,$(subst t, ,$(_WORKTREE_MARSHAL_RUN_ID)))
override _WORKTREE_MARSHAL_RUN_TIME := $(word 1,$(subst z, ,$(_WORKTREE_MARSHAL_RUN_AFTER_T)))
override _WORKTREE_MARSHAL_RUN_AFTER_Z := $(word 2,$(subst z, ,$(_WORKTREE_MARSHAL_RUN_AFTER_T)))
override _WORKTREE_MARSHAL_RUN_HEX := $(patsubst -%,%,$(_WORKTREE_MARSHAL_RUN_AFTER_Z))
override _WORKTREE_MARSHAL_RUN_RECONSTRUCTED := $(_WORKTREE_MARSHAL_RUN_DATE)t$(_WORKTREE_MARSHAL_RUN_TIME)z-$(_WORKTREE_MARSHAL_RUN_HEX)
override _WORKTREE_MARSHAL_RUN_INVALID := $(strip \
	$(call _worktree_marshal_strip_decimal,$(_WORKTREE_MARSHAL_RUN_DATE)) \
	$(if $(filter 8,$(call _worktree_marshal_character_count,$(_WORKTREE_MARSHAL_RUN_DATE))),,date-length) \
	$(call _worktree_marshal_strip_decimal,$(_WORKTREE_MARSHAL_RUN_TIME)) \
	$(if $(filter 6,$(call _worktree_marshal_character_count,$(_WORKTREE_MARSHAL_RUN_TIME))),,time-length) \
	$(call _worktree_marshal_strip_hex,$(_WORKTREE_MARSHAL_RUN_HEX)) \
	$(if $(filter 12,$(call _worktree_marshal_character_count,$(_WORKTREE_MARSHAL_RUN_HEX))),,hex-length) \
	$(subst $(_WORKTREE_MARSHAL_RUN_RECONSTRUCTED),,$(_WORKTREE_MARSHAL_RUN_ID)))

ifneq ($(strip $(_WORKTREE_MARSHAL_REQUESTED_TARGETS)),)
ifeq ($(strip $(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID)),)
ifneq ($(words $(MAKECMDGOALS)),1)
$(error $(WORKTREE_MARSHAL_DISPLAY_NAME) targets must be invoked directly and alone)
endif
endif

ifneq ($(filter $(_WORKTREE_MARSHAL_REQUIRED_TARGETS),$(_WORKTREE_MARSHAL_REQUESTED_TARGETS)),)
ifeq ($(strip $(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID)),)
ifneq ($(origin RUN),command line)
$(error Usage: make $(_WORKTREE_MARSHAL_REQUESTED_TARGETS) RUN=<run-id>)
endif
endif
ifneq ($(strip $(_WORKTREE_MARSHAL_RUN_INVALID)),)
$(error invalid $(WORKTREE_MARSHAL_DISPLAY_NAME) run ID)
endif
endif

ifneq ($(filter $(WORKTREE_MARSHAL_STATUS_TARGET),$(_WORKTREE_MARSHAL_REQUESTED_TARGETS)),)
ifeq ($(strip $(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID)),)
ifneq ($(origin RUN),undefined)
ifneq ($(origin RUN),command line)
$(error RUN must be supplied on the Make command line)
endif
ifneq ($(strip $(_WORKTREE_MARSHAL_RUN_INVALID)),)
$(error invalid $(WORKTREE_MARSHAL_DISPLAY_NAME) run ID)
endif
endif
endif
ifneq ($(strip $(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID)),)
ifneq ($(strip $(_WORKTREE_MARSHAL_RUN_INVALID)),)
$(error invalid $(WORKTREE_MARSHAL_DISPLAY_NAME) run ID)
endif
endif
endif

ifneq ($(filter $(WORKTREE_MARSHAL_RUN_TARGET),$(_WORKTREE_MARSHAL_REQUESTED_TARGETS)),)
ifneq ($(origin RUN),undefined)
$(error Usage: make $(WORKTREE_MARSHAL_RUN_TARGET))
endif
endif
endif

define _worktree_marshal_require_direct
$(if $(or $(and $(filter $@,$(MAKECMDGOALS)),$(filter 1,$(words $(MAKECMDGOALS)))),$(and $(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID),$(filter $@,$(firstword $(MAKECMDGOALS))))),,$(error $(WORKTREE_MARSHAL_DISPLAY_NAME) targets must be invoked directly and alone))
endef

.PHONY: $(_WORKTREE_MARSHAL_ALL_TARGETS)
ifneq ($(strip $(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID)),)
.PHONY: $(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID)
$(_WORKTREE_MARSHAL_POSITIONAL_RUN_ID):
	@:
endif

$(WORKTREE_MARSHAL_RUN_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_RUN_ARGUMENTS)

$(WORKTREE_MARSHAL_STATUS_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
	if [ -n '$(_WORKTREE_MARSHAL_RUN_ID)' ]; then \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_STATUS_ARGUMENTS) '$(_WORKTREE_MARSHAL_RUN_ID)'; \
	else \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_STATUS_ARGUMENTS); \
	fi

$(WORKTREE_MARSHAL_REOPEN_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_REOPEN_ARGUMENTS) '$(_WORKTREE_MARSHAL_RUN_ID)'

$(WORKTREE_MARSHAL_DIFF_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_DIFF_ARGUMENTS) '$(_WORKTREE_MARSHAL_RUN_ID)'

$(WORKTREE_MARSHAL_INTEGRATE_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_INTEGRATE_ARGUMENTS) '$(_WORKTREE_MARSHAL_RUN_ID)'

$(WORKTREE_MARSHAL_RESOLVE_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_RESOLVE_ARGUMENTS) '$(_WORKTREE_MARSHAL_RUN_ID)'

$(WORKTREE_MARSHAL_CONTINUE_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_CONTINUE_ARGUMENTS) '$(_WORKTREE_MARSHAL_RUN_ID)'

$(WORKTREE_MARSHAL_ABORT_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_ABORT_ARGUMENTS) '$(_WORKTREE_MARSHAL_RUN_ID)'

$(WORKTREE_MARSHAL_CLEAN_TARGET):
	@$(call _worktree_marshal_require_direct)unset RUN MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES; \
		exec "$(WORKTREE_MARSHAL)" $(WORKTREE_MARSHAL_GLOBAL_ARGUMENTS) $(WORKTREE_MARSHAL_CLEAN_ARGUMENTS) '$(_WORKTREE_MARSHAL_RUN_ID)'

ifeq ($(strip $(_WORKTREE_MARSHAL_PRIOR_DEFAULT_GOAL)),)
.DEFAULT_GOAL :=
else
.DEFAULT_GOAL := $(_WORKTREE_MARSHAL_PRIOR_DEFAULT_GOAL)
endif

endif
