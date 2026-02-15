# Guardian CLI Testing Makefile
# Provides convenient commands for testing and development

.PHONY: help test test-unit test-integration test-e2e test-fast test-slow coverage lint format clean install-dev

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install-dev: ## Install development dependencies
	pip install -e ".[dev]"
	pip install pytest pytest-asyncio pytest-cov pytest-timeout pytest-mock pytest-benchmark
	pip install ruff black mypy bandit safety
	@echo "✅ Development dependencies installed"

test: ## Run all tests
	pytest tests/ -v

test-unit: ## Run unit tests only
	pytest tests/unit/ -v -m unit

test-integration: ## Run integration tests only
	pytest tests/integration/ -v -m integration

test-e2e: ## Run end-to-end tests only
	pytest tests/e2e/ -v -m e2e

test-fast: ## Run fast tests only (exclude slow tests)
	pytest tests/ -v -m "not slow"

test-slow: ## Run slow tests only
	pytest tests/ -v -m slow

test-watch: ## Run tests in watch mode (auto-rerun on changes)
	pytest-watch -- tests/unit/ -v

coverage: ## Run tests with coverage report
	pytest tests/unit/ --cov=. --cov-report=html --cov-report=term-missing
	@echo "📊 Coverage report generated in htmlcov/index.html"

coverage-open: coverage ## Run coverage and open HTML report
	open htmlcov/index.html || xdg-open htmlcov/index.html

lint: ## Run linters (ruff, black, mypy)
	@echo "Running ruff..."
	ruff check .
	@echo "Running black..."
	black --check .
	@echo "Running mypy..."
	mypy tools/ core/ utils/ --ignore-missing-imports
	@echo "✅ Linting complete"

format: ## Auto-format code with black and ruff
	black .
	ruff check --fix .
	@echo "✅ Code formatted"

security: ## Run security scanners
	@echo "Running Bandit..."
	bandit -r . -ll
	@echo "Running Safety..."
	safety check
	@echo "✅ Security scan complete"

clean: ## Clean up generated files
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✅ Cleaned up generated files"

benchmark: ## Run performance benchmarks
	pytest tests/performance/ -v -m benchmark --benchmark-only

ci-test: ## Run tests like CI does
	pytest tests/unit/ -v -m unit --cov=. --cov-report=xml --cov-report=term

# =============================================================================
# Workflow-Specific Testing
# =============================================================================

test-workflows: ## Run all workflow validation tests
	pytest tests/unit/test_workflows/ -v -m unit

test-workflow-recon: ## Test recon workflow specifically
	pytest tests/ -v -k "recon" --tb=short

test-workflow-web: ## Test web_pentest workflow specifically
	pytest tests/ -v -k "web_pentest or web_workflow" --tb=short

test-workflow-network: ## Test network_pentest workflow specifically
	pytest tests/ -v -k "network_pentest or network_workflow" --tb=short

test-workflow-autonomous: ## Test autonomous workflow specifically
	pytest tests/ -v -k "autonomous" --tb=short

validate-workflows: ## Validate all workflow YAML files
	@echo "Validating workflow files..."
	@python -c "import yaml; import sys; from pathlib import Path; \
	errors = []; \
	[errors.append(f'{f}: {e}') if (e := None) or True else None \
	 for f in Path('workflows').glob('*.yaml') \
	 if not (lambda p: (yaml.safe_load(open(p)) and True) or True)(f)]; \
	print('✅ All workflows valid') if not errors else (print('\\n'.join(errors)), sys.exit(1))"
	@python -c "import yaml; from pathlib import Path; \
	wfs = list(Path('workflows').glob('*.yaml')); \
	print(f'Validated {len(wfs)} workflow files'); \
	[print(f'  ✓ {f.name}') for f in wfs]"

# =============================================================================
# HOMELAB TESTING - The 4 Workflows
# =============================================================================

# Check if tools are installed
homelab-check: ## Check if required tools are installed
	python scripts/homelab_test.py --check-tools

# Dry run (validate only, no execution)
homelab-dry: ## Validate all workflows (no execution)
	python scripts/homelab_test.py --dry-run

# Run all homelab tests
homelab: ## Run all homelab tests (validation mode)
	python scripts/homelab_test.py

# RECON workflow
homelab-recon: ## Run RECON workflow tests
	python scripts/homelab_test.py --scenario recon --dry-run

homelab-recon-live: ## Run RECON workflow LIVE (actual scans)
	python scripts/homelab_test.py --scenario recon --live

# WEB workflow
homelab-web: ## Run WEB workflow tests
	python scripts/homelab_test.py --scenario web --dry-run

homelab-web-live: ## Run WEB workflow LIVE (actual scans)
	python scripts/homelab_test.py --scenario web --live

# NETWORK workflow
homelab-network: ## Run NETWORK workflow tests
	python scripts/homelab_test.py --scenario network --dry-run

homelab-network-live: ## Run NETWORK workflow LIVE (actual scans)
	python scripts/homelab_test.py --scenario network --live

# AUTONOMOUS workflow
homelab-autonomous: ## Run AUTONOMOUS workflow tests
	python scripts/homelab_test.py --scenario autonomous --dry-run

homelab-autonomous-live: ## Run AUTONOMOUS workflow LIVE (AI-driven)
	python scripts/homelab_test.py --scenario autonomous --live

# All 4 workflows
homelab-all: ## Test all 4 workflows (validation)
	python scripts/homelab_test.py --scenario all_workflows --dry-run

homelab-all-live: ## Test all 4 workflows LIVE
	python scripts/homelab_test.py --scenario all_workflows --live

# Watch mode (auto-rerun on code changes)
homelab-watch: ## Watch mode - auto-test on file changes
	python scripts/homelab_test.py --watch

# Smoke test (quick validation)
homelab-smoke: ## Quick smoke test
	python scripts/homelab_test.py --scenario smoke --dry-run

# =============================================================================
# Quick shortcuts
# =============================================================================
t: test-unit ## Shortcut for test-unit
tc: coverage ## Shortcut for coverage
tf: format ## Shortcut for format
tw: test-workflows ## Shortcut for test-workflows
hr: homelab-recon ## Shortcut for homelab-recon
hw: homelab-web ## Shortcut for homelab-web
hn: homelab-network ## Shortcut for homelab-network
ha: homelab-autonomous ## Shortcut for homelab-autonomous
hh: homelab ## Shortcut for homelab (all)
