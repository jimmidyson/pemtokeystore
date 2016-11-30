FROM scratch

COPY out/pemtokeystore /pemtokeystore

ENTRYPOINT ["/pemtokeystore"]
CMD ["-help"]

