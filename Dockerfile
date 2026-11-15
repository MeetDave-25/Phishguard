FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PHISHGUARD_PROXY=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libgl1 libglib2.0-0 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY analyzer.py app.py ai.py inspector.py reputation.py mlmodel.py ./
COPY templates templates
COPY static static
COPY models models
RUN useradd -m app && chown -R app /app
USER app
EXPOSE 8000
# No --access-logfile: request lines are not logged. 2 workers; image OCR is the heaviest path.
CMD ["sh", "-c", "gunicorn -w 2 -b 0.0.0.0:${PORT:-8000} --timeout 60 app:app"]
