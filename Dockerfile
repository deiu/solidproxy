FROM golang

RUN \
  go get -u -x github.com/solid/solidproxy/proxy-server

EXPOSE 3129
EXPOSE 3200

CMD ["proxy-server"]
