FROM alpine

LABEL maintainer "Viktor Adam <rycus86@gmail.com>"

RUN apk add --no-cache python3

ADD requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

RUN adduser -S webapp \
    && mkdir /var/rules \
    && chown webapp:root /var/rules
USER webapp

ADD src /app
WORKDIR /app

ENV RULES_DIR /var/rules

STOPSIGNAL SIGINT

CMD [ "python3", "app.py" ]

# add app info as environment variables
ARG GIT_COMMIT
ENV GIT_COMMIT $GIT_COMMIT
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP $BUILD_TIMESTAMP
