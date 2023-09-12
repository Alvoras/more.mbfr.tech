FROM alpine:3.12

RUN apk add python3

FROM alpine:3.12

RUN apk add python3

ARG FLAG
ARG SESSION 
RUN echo "$FLAG"
RUN echo "$SESSION"
LABEL chatsubo.template="hello-flag" \
        chatsubo.flags.flag.value="$FLAG0" \
        chatsubo.flags.flag.points="25" \
        chatsubo.session="$SESSION"
RUN mkdir /secrets
RUN echo "$FLAG" > /secrets/flag
COPY ./entrypoint.sh /entrypoint.sh
WORKDIR /secrets
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
CMD /bin/sh
