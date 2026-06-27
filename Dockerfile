# pyscan — containerised so `docker run pyscan scan ...` needs zero Python setup.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# pyscan is a CLI: the image IS the command.
ENTRYPOINT ["pyscan"]
CMD ["--help"]
