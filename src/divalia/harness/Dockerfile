# Build with a reviewed, digest-pinned Linux CPython base, for example:
# docker build --build-arg BASE_IMAGE=python@sha256:<reviewed-digest> -t divalia-worker src/divalia/harness
# Configure DIVALIA_SANDBOX_IMAGE with the built sha256 image ID or a RepoDigest.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
WORKDIR /app
COPY ast_validator.py container_worker.py /app/
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/python", "-I", "-S", "-B", "/app/container_worker.py"]
