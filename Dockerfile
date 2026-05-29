FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir
COPY . .
CMD uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}
