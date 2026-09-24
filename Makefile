PY ?= python3

.PHONY: setup data dataset train-check serve-check test

setup:
	$(PY) -m pip install -r requirements.txt

data:
	$(PY) scripts/fetch_datasets.py

dataset:
	$(PY) -m chameleon.check.dataset

train-check: dataset
	$(PY) -m chameleon.check.train

serve-check:
	$(PY) -m uvicorn chameleon.check.serve:app --host 127.0.0.1 --port 8010

test:
	$(PY) -m pytest -q
