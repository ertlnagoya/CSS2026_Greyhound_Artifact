FROM python:2.7-slim

WORKDIR /app

ENV http_proxy=http://10.1.0.20:8080
ENV https_proxy=http://10.1.0.20:8080

RUN pip install --no-cache-dir numpy
RUN pip install --no-cache-dir pyrecord
RUN pip install --no-cache-dir colorama
RUN pip install --no-cache-dir flask


COPY . /app

CMD ["python", "mqtt_broker.py"]