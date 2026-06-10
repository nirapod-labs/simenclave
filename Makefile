.PHONY: help build test dylib helper notarize clean

help: ## Show targets
	@echo "Targets land with the code. See ROADMAP.md for what each milestone wires up."
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'

build: ## Build everything (wired up in M1+)
	@echo "todo: build helper and interpose"

test: ## Run tests (wired up in M1+)
	@echo "todo: unit, parity, fence"

dylib: ## Build the interposer for the simulator slice (M2)
	@echo "todo: clang -dynamiclib, iphonesimulator SDK, arm64 + x86_64, lipo"

helper: ## Build and sign the macOS helper (M1, M5)
	@echo "todo: xcodegen, xcodebuild, codesign"

notarize: ## Notarize the helper (M5)
	@echo "todo: notarytool submit, staple"

clean: ## Remove build output
	rm -rf build .turbo
