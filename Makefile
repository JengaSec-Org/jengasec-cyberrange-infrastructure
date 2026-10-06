.PHONY: help lint cells dev obs-validate obs-up obs-smoke obs-down
help:
	@echo "make lint          # static checks used by CI"
	@echo "make cells         # update team cells (needs cluster access)"
	@echo "make dev           # set up this machine (Debian 12)"
	@echo "make obs-validate  # validate observability configs and contracts"
	@echo "make obs-up        # start the local observability stack"
	@echo "make obs-smoke     # prove one event and metric arrived"
	@echo "make obs-down      # stop the stack and keep local data"

lint:
	shellcheck -x -P scripts scripts/*.sh tools/*.sh observability/tests/*.sh
	yamllint -d relaxed .github/workflows ansible contracts observability \
		scripts/cells.yaml charts/cell/Chart.yaml charts/cell/values.yaml
	jq empty .devcontainer/*.json contracts/*.schema.json \
		contracts/fixtures/*/*/*.json observability/grafana/dashboards/*.json
	helm template test charts/cell --set cell=app-01 --set image.repository=nginx > /dev/null

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
