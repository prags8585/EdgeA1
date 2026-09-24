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

serve-demo:
	$(PY) -m uvicorn chameleon.demoapp.main:app --host 127.0.0.1 --port 8200

serve-dashboard:
	$(PY) -m uvicorn chameleon.api.main:app --host 127.0.0.1 --port 8100

test:
	$(PY) -m pytest -q
