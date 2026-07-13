FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl python3 python3-yaml \
  && rm -rf /var/lib/apt/lists/*
ARG VR_VERSION=v0.76.6
RUN curl -sL "https://github.com/Velocidex/velociraptor/releases/download/${VR_VERSION}/velociraptor-${VR_VERSION}-linux-amd64" \
  -o /usr/local/bin/velociraptor \
  && chmod +x /usr/local/bin/velociraptor
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
WORKDIR /opt/velociraptor
EXPOSE 8000 8001 8002
ENTRYPOINT ["/entrypoint.sh"]
CMD ["frontend", "-v"]
