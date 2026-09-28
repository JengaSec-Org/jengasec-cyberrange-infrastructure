.PHONY: help lint cells dev
help:
	@echo "make lint    # the same checks CI runs"
	@echo "make cells   # provision or update all team cells (needs cluster access)"
	@echo "make dev     # set up this machine (Debian 12)"

lint:
	shellcheck scripts/*.sh tools/*.sh
	yamllint -d relaxed ansible charts observability
	helm template test charts/cell --set cell=app-01 --set image.repository=nginx > /dev/null

cells:
	./scripts/provision-cells.sh

dev:
	./tools/bootstrap-dev-vm.sh
