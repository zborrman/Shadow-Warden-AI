FROM python:3.11-slim

WORKDIR /admin

# Install only what the admin UI needs
RUN pip install --no-cache-dir \
    streamlit==1.35.0 \
    requests==2.32.3 \
    pandas==2.2.2

COPY app.py .

# Non-root user
RUN adduser --disabled-password --uid 10001 appuser
USER appuser

EXPOSE 8502

CMD ["streamlit", "run", "app.py", \
     "--server.port=8502", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
