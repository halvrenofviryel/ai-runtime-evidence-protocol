PYTHON ?= python3
DEMO_ARGS ?=

.PHONY: demo demo-test

demo:
	$(PYTHON) scripts/demo.py $(DEMO_ARGS)

demo-test:
	$(PYTHON) scripts/test_demo.py
