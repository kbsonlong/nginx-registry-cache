FROM python:3.12-slim

RUN useradd --system --uid 10001 --create-home proxyadmin \
    && mkdir -p /var/lib/proxy-admin \
    && chown proxyadmin:proxyadmin /var/lib/proxy-admin

COPY app.py /app/app.py
COPY static /app/static

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.115.12 uvicorn[standard]==0.34.2

USER proxyadmin
EXPOSE 8081

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8081", "--no-access-log"]
