FROM python:3.11-slim 

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY src /app/src
COPY contracts /app/contracts
COPY configs /app/configs

RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -e .

CMD ["solfuzz", "doctor"]


