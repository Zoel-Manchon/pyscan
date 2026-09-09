# pyscan — containerised so `docker run pyscan scan ...` needs zero Python setup.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
# The TUI extra is included so `sniff --tui` and `monitor --tui` work out of the box.
RUN pip install --no-cache-dir ".[tui]"

# pyscan is a CLI: the image IS the command.
ENTRYPOINT ["pyscan"]
CMD ["--help"]
