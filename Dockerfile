FROM python:3.7.10-stretch

RUN apt-get update && \
    apt-get install -y nasm

RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pip -U && \
    pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip install torch torchvision

COPY . /app

WORKDIR /app

RUN pip install -r requirements.txt

ENTRYPOINT [ "/bin/bash", "./entrypoint.sh" ]
