# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
NETWORKING_APPS = 01_XDP_SimpleDrop 02_XDP_DropByIP 03_TC_FIBLookup 04_SK_SKB_filter

# Function to check if submodules are initialized
define check_submodules
    @if [ ! -f libs/libbpf/src/Makefile ]; then \
        echo "Initializing submodules..."; \
        git submodule update --init --recursive; \
    fi

	@if [ ! -f libs/bpftool/libbpf/src/Makefile ]; then \
		echo "Initializing submodules..."; \
		pushd .; \
		cd libs/bpftool; \
		git submodule update --init --recursive; \
		popd; \
	fi
endef

.PHONY: all
all: check-submodules all-networking all-system

.PHONY: check-submodules
check-submodules:
	$(call check_submodules)

all-networking: check-submodules
	$(call msg,ALL-NETWORKING)
	$(Q)$(foreach app,$(NETWORKING_APPS),make -C src/networking/$(app);)

all-system:
	$(call msg,ALL-SYSTEM)
	make -C src/system

clean:
	$(call msg,CLEAN)
	$(Q)make -C src/system clean
	$(Q)$(foreach app,$(NETWORKING_APPS),make -C src/networking/$(app) clean;)
	$(Q)rm -rf .output