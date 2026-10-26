FROM python:3.9-slim

ENV AWS_SECRET_KEY="DEMO_INSECURE_SECRET_VALUE"
ENV DEBUG_MODE="true"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y openssh-server

COPY . .

EXPOSE 5000
EXPOSE 22

CMD ["python", "app.py"]
