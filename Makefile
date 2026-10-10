.PHONY: help lint contracts cells dev obs-validate obs-up obs-smoke obs-down
help:
	@echo "make lint          # the same checks CI runs"
	@echo "make contracts     # validate shared contracts and fixtures"
	@echo "make cells         # update team cells (needs cluster access)"
	@echo "make dev           # set up this machine (Debian 12)"
	@echo "make obs-validate  # validate observability configs and contracts"
	@echo "make obs-up        # start the observability stack"
	@echo "make obs-smoke     # prove one event and metric arrived"
	@echo "make obs-down      # stop the stack and keep data"

lint:
	shellcheck -x -P scripts scripts/*.sh tools/*.sh observability/tests/*.sh
	yamllint -c .yamllint.yml .github ansible charts contracts observability scripts
	jq empty contracts/*.schema.json \
		contracts/fixtures/*/*/*.json observability/grafana/dashboards/*.json
	helm template test charts/cell --set image.repository=nginx > /dev/null
	$(MAKE) contracts

contracts:
	python3 scripts/validate-contracts.py

cells:
	./scripts/provision-cells.sh

dev:
	./tools/bootstrap-dev-vm.sh

obs-validate:
	./scripts/validate-observability.sh

obs-up:
	./scripts/start-observability.sh

obs-smoke:
	./scripts/smoke-observability.sh

obs-down:
	./scripts/stop-observability.sh
