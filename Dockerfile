FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN set -ex \
#    && pip config set global.index-url https://pypi.douban.com/simple/ \
    && pip install -r requirements.txt \
COPY xunlei_k.py .
CMD ["python", "-u", "xunlei_k.py"]
