https://stackoverflow.com/questions/75602063/pip-install-r-requirements-txt-is-failing-this-environment-is-externally-mana

This is due to your distribution adopting PEP 668 – Marking Python base environments as “externally managed”.

TL;DR: Use a venv:
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

to exit virtual environment
	`deactivate`


Show what pip packages are installed
	`pip list

Uninstall packages
	`pip uninstall <package>`

Autorecon as sudo
	python3 -m venv .venv
	source .venv/bin/activate
	`sudo env "PATH=$PATH" autorecon <ip>

Git-dumper
	python3 -m venv .venv
	source .venv/bin/activate
	pip install git-dumper
	