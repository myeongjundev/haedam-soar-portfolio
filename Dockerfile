FROM node:24-bookworm-slim AS frontend
WORKDIR /build
COPY haedam-portal-frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY haedam-portal-frontend/index.html haedam-portal-frontend/vite.config.js ./
COPY haedam-portal-frontend/public ./public
COPY haedam-portal-frontend/src ./src
RUN npm run build

FROM python:3.12-slim AS portal
WORKDIR /app
COPY haedam-portal-backend/requirements-dev.lock ./
RUN pip install --no-cache-dir -r requirements-dev.lock \
    && useradd --uid 10001 --no-create-home portal \
    && install -d -o portal /app/instance
COPY haedam-portal-backend/src ./src
COPY haedam-portal-backend/migrations ./migrations
COPY --from=frontend /build/dist ./frontend
ENV PYTHONPATH=/app/src FRONTEND_DIST=/app/frontend PYTHONUNBUFFERED=1
USER portal
EXPOSE 5000
CMD ["sh", "-ec", "flask --app haedam_portal:create_app db upgrade && exec waitress-serve --host=0.0.0.0 --port=5000 --call haedam_portal:create_app"]
