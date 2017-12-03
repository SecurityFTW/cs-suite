# Run the tool as docker container using below command, reports will be in local system
#
# docker run -v `pwd`/aws:/root/.aws -v `pwd`/reports:/app/reports cs-suite
#
FROM python:2.7-alpine
LABEL MAINTAINER="Madhu Akula"

COPY . /app
RUN apk add --no-cache sshpass gcc bash \
    && apk --update add grep \
    && pip install -r /app/requirements.txt \
    && pip install awscli --ignore-installed six

ENTRYPOINT ["python", "/app/cs.py"]
