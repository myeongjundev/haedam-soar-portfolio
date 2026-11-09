FROM python:3.12-slim
RUN pip install --no-cache-dir Flask==3.1.3 Werkzeug==3.1.9
WORKDIR /app
COPY ticket_store ./ticket_store
RUN useradd --uid 10001 --no-create-home store && mkdir /data && chown store /data
USER store
ENV TICKET_STORE_DB=/data/tickets.db PYTHONUNBUFFERED=1
EXPOSE 8088 8089
CMD ["python", "-m", "ticket_store"]
