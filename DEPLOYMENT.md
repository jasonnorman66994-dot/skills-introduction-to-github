# Deployment Configuration for Zero Trust Security API

## Docker Setup

### Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run the API
CMD ["python", "-m", "uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  zero-trust-api:
    build: .
    container_name: zero-trust-api
    ports:
      - "8000:8000"
    environment:
      - LOG_LEVEL=INFO
      - WORKERS=4
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
```

## Kubernetes Deployment

### Namespace and ConfigMap

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: zero-trust

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: zero-trust-config
  namespace: zero-trust
data:
  LOG_LEVEL: "INFO"
  WORKERS: "4"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zero-trust-api
  namespace: zero-trust
  labels:
    app: zero-trust-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: zero-trust-api
  template:
    metadata:
      labels:
        app: zero-trust-api
    spec:
      containers:
      - name: api
        image: zero-trust-api:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
          name: http
        envFrom:
        - configMapRef:
            name: zero-trust-config
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 2
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: zero-trust-api
  namespace: zero-trust
  labels:
    app: zero-trust-api
spec:
  type: ClusterIP
  selector:
    app: zero-trust-api
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
    name: http
```

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: zero-trust-api-hpa
  namespace: zero-trust
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: zero-trust-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Environment Variables

```bash
# API Configuration
LOG_LEVEL=INFO              # Log level (DEBUG, INFO, WARNING, ERROR)
WORKERS=4                   # Number of worker processes
RATE_LIMIT=100             # Requests per minute per IP
SESSION_TIMEOUT=3600       # Session timeout in seconds
AUTH_ATTEMPTS_MAX=5        # Maximum failed auth attempts
AUTH_LOCKOUT_DURATION=300  # Lockout duration in seconds

# Security
SECURE_COOKIES=true        # Use secure cookies
SAME_SITE=Strict           # SameSite cookie attribute
CORS_ORIGINS=*             # CORS allowed origins

# Caching
CACHE_TTL=300              # Cache TTL in seconds
CACHE_MAX_SIZE=10000       # Maximum cache size
```

## Production Deployment Checklist

- [ ] Set up SSL/TLS certificates
- [ ] Configure environment variables securely (use secrets management)
- [ ] Enable rate limiting and brute force protection
- [ ] Set up centralized logging (ELK, Splunk, etc.)
- [ ] Configure monitoring and alerting
- [ ] Set up database backups (if using persistent storage)
- [ ] Enable request/response logging for audit trails
- [ ] Configure CORS appropriately
- [ ] Set up CI/CD pipeline for automated deployment
- [ ] Perform security scanning and penetration testing
- [ ] Document runbooks and incident response procedures
- [ ] Establish SLA and monitoring KPIs

## Deployment Commands

### Docker
```bash
# Build image
docker build -t zero-trust-api:latest .

# Run container
docker run -p 8000:8000 zero-trust-api:latest

# Docker Compose
docker-compose up -d
```

### Kubernetes
```bash
# Create namespace
kubectl create namespace zero-trust

# Apply configuration
kubectl apply -f deployment/

# Check status
kubectl get pods -n zero-trust
kubectl get svc -n zero-trust

# Port forwarding for testing
kubectl port-forward -n zero-trust svc/zero-trust-api 8000:80

# View logs
kubectl logs -n zero-trust deployment/zero-trust-api -f

# Delete deployment
kubectl delete -f deployment/
```

## Monitoring Endpoints

- Health: `GET /health`
- Metrics: (implement `/metrics` endpoint using Prometheus)
- Logs: Centralized logging system

## Scaling Considerations

1. **Authentication Cache**: Use Redis or similar for distributed caching
2. **Session Storage**: Use centralized session store (Redis, Memcached)
3. **Audit Logs**: Use centralized logging (ELK Stack, Splunk)
4. **Rate Limiting**: Use Redis-backed rate limiter for distributed systems
5. **Database**: Add persistent storage layer if needed

## Security Considerations

- All API calls over HTTPS only
- API keys/tokens in Authorization header
- Rate limiting enabled
- Input validation on all endpoints
- Audit logging for all sensitive operations
- Regular security scanning
- Dependency vulnerability scanning
