FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
COPY xunlei_k.py .
RUN set -ex \
#    && pip config set global.index-url https://pypi.douban.com/simple/ \
    && pip install -r requirements.txt
CMD ["python", "-u", "xunlei_k.py"]
