FROM python:3.12-slim

WORKDIR /app

RUN useradd -m appuser

COPY . /app

USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
