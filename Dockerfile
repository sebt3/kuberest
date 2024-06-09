ARG REG=cgr.dev
ARG PRJ=chainguard/static
ARG TAG=latest
FROM ${REG}/${PRJ}:${TAG}
COPY --chown=nonroot:nonroot ./controller /app/
EXPOSE 8080
ENTRYPOINT ["/app/controller"]
