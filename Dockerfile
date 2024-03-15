FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN set -ex \
    && pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
COPY xunlei_k.py .
CMD ["python", "-u", "xunlei_k.py"]
