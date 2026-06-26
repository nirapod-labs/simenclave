# The one command surface for the repo. No build flags live here: the native C
# build lives in CMakeLists.txt, the Swift build in each Package.swift. This
# delegates to cmake, swift, and biome and orchestrates the integration runs.

SHELL := /bin/bash
export DEVELOPER_DIR ?= /Applications/Xcode.app/Contents/Developer

# Resolve the simulator SDK through the pinned Xcode, not the active xcode-select
# (which may be the Command Line Tools, with no iOS SDKs).
SIM_SDK      := $(shell DEVELOPER_DIR=$(DEVELOPER_DIR) xcrun --sdk iphonesimulator --show-sdk-path)
SIM_TARGET   := arm64-apple-ios15.0-simulator
WATCH_SDK    := $(shell DEVELOPER_DIR=$(DEVELOPER_DIR) xcrun --sdk watchsimulator --show-sdk-path)
WATCH_TARGET := arm64-apple-watchos10.0-simulator
SWIFT_PKGS   := packages/host-core packages/protocol/swift apps/helper tools/simenclavectl

# Code-signing identity for `make sign`. Default is ad-hoc, which works on any
# machine with no certificate. Pass a keychain identity for a named local build,
# e.g. make sign SIGN_ID="SimEnclave Dev (Local)". This is a local-use signature,
# not Developer ID or notarization; the shippable signed build is M5.
SIGN_ID ?= -
C_FILES    := $(shell find packages/interpose/src packages/interpose/include packages/interpose/tests \
                            packages/protocol/c/src packages/protocol/c/include packages/protocol/c/tests \
                            -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null)

.PHONY: help bootstrap configure build dylib helper test test-portable \
        fence docs sign release mechanism-c mechanism-d mechanism-d-watchos \
        cryptokit-probe lint format clean

help: ## Show targets
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

bootstrap: ## Fresh clone to ready: brew, pnpm, hooks, cmake configure (fetches Dobby)
	@command -v brew >/dev/null && brew bundle || echo "brew not found; skipping Brewfile"
	pnpm install
	pnpm exec lefthook install
	@$(MAKE) configure

configure: ## Configure the CMake build trees (host, iphonesimulator, watchsimulator)
	cmake -S . -B build -DCMAKE_OSX_ARCHITECTURES=arm64
	cmake -S . -B build-sim -DSIMENCLAVE_SIM_SLICE=ON -DSIMENCLAVE_SIM_PLATFORM=ios \
	  -DCMAKE_OSX_SYSROOT="$(SIM_SDK)" -DCMAKE_OSX_ARCHITECTURES=arm64 \
	  -DCMAKE_C_FLAGS="-target $(SIM_TARGET)" -DCMAKE_CXX_FLAGS="-target $(SIM_TARGET)"
	cmake -S . -B build-watchsim -DSIMENCLAVE_SIM_SLICE=ON -DSIMENCLAVE_SIM_PLATFORM=watchos \
	  -DCMAKE_OSX_SYSROOT="$(WATCH_SDK)" -DCMAKE_OSX_ARCHITECTURES=arm64 \
	  -DCMAKE_C_FLAGS="-target $(WATCH_TARGET)" -DCMAKE_CXX_FLAGS="-target $(WATCH_TARGET)"

build: configure ## Build the native slices (cmake) and the Swift packages
	cmake --build build -j
	cmake --build build-sim -j
	cmake --build build-watchsim -j
	@for p in $(SWIFT_PKGS); do echo "== swift build: $$p =="; ( cd $$p && xcrun swift build ) || exit 1; done

dylib: configure ## Build the injectable interposer dylibs (ios and watchos sim slices)
	cmake --build build-sim --target simenclave_interpose -j
	cmake --build build-watchsim --target simenclave_interpose -j

helper: ## Build just the helper executable
	cd apps/helper && xcrun swift build

sign: ## Build the release helper and codesign it (SIGN_ID=- ad-hoc; pass an identity for a named build)
	cd apps/helper && xcrun swift build -c release
	codesign -s "$(SIGN_ID)" --force apps/helper/.build/release/simenclave-helper
	@codesign -dvv apps/helper/.build/release/simenclave-helper 2>&1 | grep -E "Authority|Signature|Identifier"

release: ## Cut a release: bump VERSION + mirrors, commit, tag, push (make release VERSION=x.y.z); the tag triggers the release workflow
	@bash scripts/release.sh "$(VERSION)"

test: build ## Run the C tests (ctest), the Swift tests, the fence + its self-test, and mechanism C
	ctest --test-dir build --output-on-failure
	@for p in $(SWIFT_PKGS); do echo "== swift test: $$p =="; ( cd $$p && xcrun swift test ) || exit 1; done
	@bash scripts/fence-check.sh
	@bash scripts/fence-selftest.sh
	@$(MAKE) mechanism-c

test-portable: ## The subset that runs on any runner (no SEP, no Xcode): C codec + biome + fence
	ctest --test-dir build --output-on-failure -R protocol_codec
	pnpm exec biome check .
	bash scripts/fence-check.sh

fence: ## The static fence assertions; the runtime legs ride mechanism-d
	bash scripts/fence-check.sh

docs: ## Generate the C API docs (Doxyfile); any doc warning fails the run
	doxygen Doxyfile

mechanism-c: ## Host integration proof: hooks route to the helper, signature verifies
	bash packages/interpose/tests/run-mechanism-c.sh

mechanism-d: ## Simulator integration proof (M0 exit criterion): in-sim signature verifies
	bash packages/interpose/tests/run-mechanism-d.sh

mechanism-d-watchos: ## watchOS Simulator integration proof: in-sim signature verifies (needs the watchOS runtime)
	bash packages/interpose/tests/run-mechanism-d-watchos.sh

cryptokit-probe: ## Probe: CryptoKit SecureEnclave softwares in the sim, so it is not bridged
	bash packages/interpose/tests/run-cryptokit-probe.sh

lint: ## biome + swiftlint + clang-tidy (off the CMake compile database)
	pnpm exec biome check .
	-swiftlint lint --quiet
	-clang-tidy -p build $(filter %.c,$(C_FILES))

format: ## biome + swiftformat + clang-format, each off its existing config
	pnpm exec biome format --write .
	-swiftformat . --quiet
	-clang-format -i $(C_FILES)

clean: ## Remove the build trees
	rm -rf build build-sim build-watchsim .turbo
