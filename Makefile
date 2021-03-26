init:
	@echo ""
	@echo "Running Cargo utils"
	@echo ""
	@cargo fmt
	@cargo clippy
.PHONY: init