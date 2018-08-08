# Run the tool as docker container using below command, reports will be in local system
#
# docker run -v `pwd`/aws:/root/.aws -v `pwd`/reports:/app/reports cs-suite
#
FROM python:2.7-alpine
LABEL MAINTAINER="Madhu Akula"

COPY . /app

WORKDIR /app

RUN apk update && apk add --no-cache grep sshpass curl bash \
    && pip install -r requirements.txt \
    && pip install awscli --ignore-installed six

ENTRYPOINT ["python", "/app/cs.py"]
