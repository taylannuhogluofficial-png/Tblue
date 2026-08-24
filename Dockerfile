FROM python:3.12-slim

WORKDIR /app

COPY setup.py pyproject.toml README.md ./
COPY tblue/ ./tblue/

RUN pip install --no-cache-dir -e . \
 && pip install --no-cache-dir playwright \
 && playwright install --with-deps chromium

ENTRYPOINT ["tblue"]
CMD ["--help"]
