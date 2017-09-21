FROM alpine:edge

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

COPY out/pemtokeystore /pemtokeystore

ENTRYPOINT ["/pemtokeystore"]
CMD ["-help"]
