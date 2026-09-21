FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY server.py materializer.py soc_analysis.py soc_automation.py soc_pipeline.py soc_workflows.py cve_exposure.py soc_contract.py \
    cyfirma_research.py cyfirma_taxii.py cyfirma_org_vulnerability.py defender_xdr.py entity_resolver.py detection_taxonomy.py telemetry_contract.py .
COPY static ./static

RUN useradd -r -u 1000 -g root dashboard
RUN mkdir /app/runtime /app/cmdb && chown 1000:0 /app/runtime /app/cmdb
USER 1000:0

EXPOSE 8088
CMD ["python", "server.py"]
