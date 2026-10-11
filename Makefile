.PHONY: help lint contracts cells dev
help:
	@echo "make lint    # the same checks CI runs"
	@echo "make contracts # validate shared contracts and fixtures"
	@echo "make cells   # provision or update all team cells (needs cluster access)"
	@echo "make dev     # set up this machine (Debian 12)"

lint:
	shellcheck -x -P scripts scripts/*.sh tools/*.sh
	yamllint -c .yamllint.yml .github ansible charts contracts observability scripts
	helm template test charts/cell --set image.repository=nginx > /dev/null
	$(MAKE) contracts

contracts:
	python3 scripts/validate-contracts.py

cells:
	./scripts/provision-cells.sh

dev:
	./tools/bootstrap-dev-vm.sh
