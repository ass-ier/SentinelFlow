.PHONY: install dev test lint format validate demo reset benchmark

install dev test lint format validate:
	python3 scripts/manage.py $@

demo:
	.venv/bin/python scripts/demo_reset.py --seed

reset:
	.venv/bin/python scripts/demo_reset.py

benchmark:
	.venv/bin/python scripts/benchmark_detection.py
