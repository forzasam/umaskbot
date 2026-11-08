FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gatekeeper/ gatekeeper/
RUN mkdir -p /app/data && useradd --create-home --uid 10001 bot && chown -R bot:bot /app/data
USER bot
CMD ["python", "-m", "gatekeeper"]
