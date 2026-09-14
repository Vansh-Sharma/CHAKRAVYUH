# Helm Chart

> Helm chart for CHAKRAVYUH OS v1.0.0 — **PLANNED for Phase 9 (Marvel)**.

A dedicated Helm chart is planned for Phase 9. Until it ships, use the manual
`kubectl` workflow below. The planned chart structure is documented for reference.

## Interim: Manual kubectl Workflow

### 1. Namespace and Secrets

```bash
kubectl create namespace chakravyuh

kubectl create secret generic chakravyuh-tls \
  --from-file=tls.crt=./certs/tls.crt \
  --from-file=tls.key=./certs/tls.key \
  -n chakravyuh

kubectl create secret generic chakravyuh-secrets \
  --from-literal=upstream_api_key="$CHAKRAVYUH_UPSTREAM_API_KEY" \
  -n chakravyuh
```

### 2. Apply Manifests

```bash
kubectl apply -f k8s/ -n chakravyuh
```

### 3. Verify

```bash
kubectl get all -n chakravyuh
kubectl rollout status deployment/chakravyuh -n chakravyuh
```

### 4. Update Config

```bash
kubectl create configmap chakravyuh-config --from-file=config.yaml=./config.yaml \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/chakravyuh -n chakravyuh
```

### 5. Teardown

```bash
kubectl delete namespace chakravyuh
```

## Planned Chart Structure

The Phase 9 Helm chart will follow this layout:

```
helm/chakravyuh/
├── Chart.yaml
├── values.yaml
├── README.md
└── templates/
    ├── _helpers.tpl
    ├── namespace.yaml
    ├── configmap.yaml
    ├── secret.yaml
    ├── deployment.yaml
    ├── service.yaml
    ├── ingress.yaml
    ├── hpa.yaml
    ├── networkpolicy.yaml
    └── NOTES.txt
```

### Planned `values.yaml`

```yaml
replicaCount: 3
image:
  repository: vinomoid/chakravyuh
  tag: "1.0.0-tls-redis"
  pullPolicy: IfNotPresent
config:
  server: { listen: "0.0.0.0:8443" }
  redis: { url: "redis://chakravyuh-redis.chakravyuh.svc:6379" }
  rate_limit: { enabled: true, requests_per_minute: 60 }
  geo_fence: { enabled: true, db_path: "/app/data/GeoLite2-City.mmdb" }
  audit: { enabled: true }
secrets:
  upstreamApiKey: ""
  tls: { crt: "", key: "" }
ingress:
  enabled: true
  className: nginx
  host: chakravyuh.example.com
  tlsTermination: true
resources:
  requests: { cpu: 500m, memory: 256Mi }
  limits: { cpu: "2", memory: 1Gi }
hpa: { enabled: true, minReplicas: 2, maxReplicas: 10, targetCPUUtilization: 70 }
networkPolicy: { enabled: true }
rustLog: "chakravyuh=info"
```

### Planned Install Commands

```bash
# Install
helm install chakravyuh helm/chakravyuh \
  --namespace chakravyuh --create-namespace \
  --set secrets.upstreamApiKey="$CHAKRAVYUH_UPSTREAM_API_KEY" \
  --set-file secrets.tls.crt=./certs/tls.crt \
  --set-file secrets.tls.key=./certs/tls.key

# Upgrade
helm upgrade chakravyuh helm/chakravyuh --namespace chakravyuh

# Uninstall
helm uninstall chakravyuh --namespace chakravyuh
```

## Roadmap Reference

| Phase | Name | Helm Status |
|-------|------|-------------|
| 1–8   | Foundation → Drishti | Raw manifests (this document) |
| 9     | Marvel | Official Helm chart release |

Track progress in the project roadmap.


*CHAKRAVYUH OS v1.0.0 · VINOMOID · Deployment Documentation*
