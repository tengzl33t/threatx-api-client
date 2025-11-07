# Installation guide

## Install with pip:

1. Install compatible Python version: >=3.10
2. Install package
    - Latest release:
      `LATEST=$(curl -s https://api.github.com/repos/tengzl33t/threatx-api-client/releases/latest | grep browser_download_url | grep .whl | cut -d '"' -f 4) && pip install $LATEST`
    - Latest code: `pip install https://github.com/tengzl33t/threatx-api-client/archive/refs/heads/main.tar.gz`

## Install with uv:

1. Install compatible Python version: >=3.10 and [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Close repository
    - Git: `git clone git@github.com:tengzl33t/threatx-api-client.git`
    - HTTPS: `git clone https://github.com/tengzl33t/threatx-api-client.git`
3. Sync dependencies
    - Only required: `uv sync`
    - Everything: `uv sync --all-groups`
4. Import library to where you want

## Add as library to existing project

- Poetry: `poetry add git+https://github.com/tengzl33t/threatx-api-client.git`
- uv: `uv add git+https://github.com/tengzl33t/threatx-api-client.git`