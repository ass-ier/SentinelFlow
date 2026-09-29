.PHONY: install dev test lint format validate security security-tools demo reset benchmark serve

install dev test lint format validate security security-tools:
	python3 scripts/manage.py $@

demo:
	.venv/bin/python scripts/demo_reset.py --seed

reset:
	.venv/bin/python scripts/demo_reset.py

benchmark:
	.venv/bin/python scripts/benchmark_detection.py

serve:
	.venv/bin/python scripts/serve.py
