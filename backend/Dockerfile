FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

# 1) Dependencies dulu agar layer cache efektif saat hanya kode yang berubah.
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# 2) Kode backend. Dataset besar (data/, modul_a3/) TIDAK di-COPY ke image;
#    di-mount read-only via volume di docker-compose.yml supaya image tetap ramping.
COPY backend/ /app/backend/

EXPOSE 8000

# Jalankan sebagai package (import absolut "backend.xxx" mensyaratkan WORKDIR=/app).
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
