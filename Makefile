# Makefile for Smart Contract Audit Tool

.PHONY: help install test lint clean

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies
	pip install -r requirements.txt
	pip install -e .

test:  ## Run tests
	pytest tests/ -v

lint:  ## Run linter
	flake8 smart_audit/
	black --check smart_audit/

clean:  ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

demo:  ## Run demo
	python demo.py

serve:  ## Start web server
	python cli.py serve --port 8000
