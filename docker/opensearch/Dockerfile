# OpenSearch 2.12 + ingest-attachment (requis OpenCTI : pipeline processor « attachment »)
FROM opensearchproject/opensearch:2.12.0
USER root
RUN /usr/share/opensearch/bin/opensearch-plugin install --batch ingest-attachment \
  && chown -R 1000:0 /usr/share/opensearch
USER 1000
