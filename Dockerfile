FROM python:3.11-slim

# Non-root user for security
RUN useradd -m -u 1000 dgic

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only production source files — no demo, test, or proof files
COPY circuit_breaker.py \
     config.py \
     decision_contract_standardization.py \
     dgic_adapter.py \
     dgic_contract.py \
     dgic_contract_validator.py \
     dgic_service.py \
     hash_validator.py \
     ksml_input_enforcement.py \
     live_pipeline.py \
     logger.py \
     metrics.py \
     middleware.py \
     sutradhara_compliance.py \
     tracing.py \
     ./

# Switch to non-root
USER dgic

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=4)"

# Production entry: gunicorn with uvicorn workers
# Worker count overridden at runtime via DGIC_WORKERS env var
CMD ["sh", "-c", "gunicorn dgic_service:app \
     --worker-class uvicorn.workers.UvicornWorker \
     --workers ${DGIC_WORKERS:-4} \
     --bind 0.0.0.0:8000 \
     --timeout 30 \
     --keep-alive 5 \
     --access-logfile - \
     --error-logfile -"]
