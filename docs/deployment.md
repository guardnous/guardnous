# Deployment

[← Back to the README](../README.md)

Docker Compose is the supported deployment today; see [Getting started](getting-started.md). Kubernetes is a preview.

### Helm Chart (preview)

Kubernetes support is planned for a future release; the chart is included now so it can be tried and reviewed. The `helm/guardnous/` chart is written to deploy all components:

| Component | K8s Resource | Autoscaling |
|---|---|---|
| API Server | Deployment | HPA 3–10 replicas |
| Web Frontend | Deployment | HPA 2–8 replicas |
| Celery Workers | Deployment | HPA 3–15 replicas |
| Celery Beat | Deployment | 1 replica (leader) |

### Bring Your Own Database

GuardNous does **not** force you to run PostgreSQL or Redis inside the cluster. The setup wizard and Helm values support external endpoints:

```yaml
# values-production.yaml
database:
  externalUrl: "postgresql://user:pass@your-rds-host:5432/guardnous?sslmode=require"
redis:
  externalUrl: "redis://your-elasticache-host:6379"
secrets:
  secretKey: "<openssl rand -hex 32>"
  encryptionKey: "<openssl rand -base64 32 | tr '+/' '-_'>"
ingress:
  host: guardnous.example.com
```

The chart derives the async and sync database URLs and the Celery broker and result URLs from these two addresses, and refuses to render if the database, Redis or either key is missing. Schema migrations run once, in an init container of the API pod, under a database lock. The web image has the API address compiled in, so build it with `--api-url`. The chart has not yet been tested on a cluster.

### CI-Agnostic Build & Deploy

We don't lock you into GitHub Actions or any CI system. The scripts work anywhere:

| Script | What It Does |
|--------|--------------|
| `scripts/build-images.sh` | Builds API + Web container images, tags, pushes to any registry |
| `scripts/deploy.sh` | Validates config, runs `helm upgrade --install`, fails fast on missing values |
| `scripts/setup-k8s.sh` | Interactive wizard — generates `values-generated.yaml` from your answers |

---

