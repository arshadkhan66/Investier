FROM python:3.12-slim

WORKDIR /app

# Build tools are needed to compile llama-cpp-python from source.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x run.sh scripts/download_model.sh

ENV PORT=8000
EXPOSE 8000

CMD ["./run.sh"]
