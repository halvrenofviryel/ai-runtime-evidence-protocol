PYTHON ?= python3
DEMO_ARGS ?=

.PHONY: demo demo-test challenge-test

demo:
	$(PYTHON) scripts/demo.py $(DEMO_ARGS)

demo-test:
	$(PYTHON) scripts/test_demo.py

challenge-test:
	$(PYTHON) interop/v02-producer-challenge/test_challenge.py
