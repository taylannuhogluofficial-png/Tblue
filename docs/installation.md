# Installation

## Requirements

- Python 3.10 or higher
- pip

## Install from PyPI

```bash
pip install tblue
```

## Install from source

```bash
git clone https://github.com/taylannuhogluofficial-png/Tblue.git
cd Tblue
pip install -e .
```

This makes the `tblue` command available globally.

## Verify installation

```bash
python -m tblue --version
```

## Dependencies

| Package        | Purpose                        |
|---------------|--------------------------------|
| requests      | HTTP requests                  |
| beautifulsoup4 | HTML parsing                  |
| lxml          | Fast HTML parser backend       |
| urllib3       | URL handling                   |

## Virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```
