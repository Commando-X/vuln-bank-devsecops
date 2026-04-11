# VulnBank — Kubernetes Infrastructure Hardening

This module demonstrates how to wrap the VulnBank application in
Kubernetes-native security controls, simulating the **compensating
control** approach used in financial sector environments.

The core idea: code will always be vulnerable. Applying layered
infrastructure controls around it is what makes it safer in practice,
and is exactly how real banks protect legacy and third-party
applications they cannot fully patch.

> This module complements the existing CI/CD pipeline in this repo
> (SAST → SCA → container scan → DAST). That pipeline secures the
> **build**. This module secures the **runtime infrastructure**.

---

## Deployment Model

**This module is a manual lab setup, not an automated pipeline step.**

It is important to understand how this relates to the existing
`deploy/deploy.sh` script in this repo:

| | `deploy/deploy.sh` | This module |
|---|---|---|
| **Target** | EC2 instance | Kubernetes cluster (k3s, Minikube, etc.) |
| **Runtime** | Bare Docker container | Kubernetes pods + namespaces |
| **How it runs** | Called by the GitHub Actions `deploy` job | Applied manually with `kubectl` and `helm` |
| **Purpose** | Automated deployment of the app | Hardening the infra around the app |

These are two different deployment targets. They are not interchangeable.
The K8s module is not a replacement for `deploy.sh`, it is a
separate environment for practising infrastructure security controls.

### How this would integrate into a real pipeline

In a production engineering team, the K8s manifests and Kong config in
this module would be applied by a CI/CD step after the security scans
pass, not by a developer running commands manually. That step would
look roughly like this in a GitHub Actions workflow:

```yaml
deploy-k8s:
  name: Deploy to Kubernetes
  needs: [sast, sca, container_scan, iac_scan, zap_scan]
  runs-on: ubuntu-latest
  if: github.ref == 'refs/heads/main' && github.event_name == 'push'
  steps:
    - uses: actions/checkout@v4

    - name: Set up kubectl
      uses: azure/setup-kubectl@v3

    - name: Configure kubeconfig
      # The pipeline needs a kubeconfig stored as a secret pointing
      # at the target cluster. In AWS this would be an EKS cluster;
      # in GCP a GKE cluster; on-prem it would be a k3s or kubeadm cluster.
      run: |
        mkdir -p ~/.kube
        echo "${{ secrets.KUBECONFIG }}" > ~/.kube/config
        chmod 600 ~/.kube/config

    - name: Install Helm
      uses: azure/setup-helm@v3

    - name: Apply namespaces and manifests
      run: |
        kubectl apply -f deploy/k8s-infra-hardening/manifests/namespaces.yaml
        kubectl apply -f deploy/k8s-infra-hardening/manifests/network-policies/
        kubectl apply -f deploy/k8s-infra-hardening/manifests/postgres/
        kubectl apply -f deploy/k8s-infra-hardening/manifests/vuln-bank/

    - name: Apply Kong config
      run: |
        kubectl create configmap kong-config \
          --from-file=kong.yaml=deploy/k8s-infra-hardening/kong/kong.yaml \
          -n kong --dry-run=client -o yaml | kubectl apply -f -
        helm upgrade --install kong kong/ingress \
          -n kong -f deploy/k8s-infra-hardening/kong/values.yaml
```

This pattern requires a `KUBECONFIG` secret in your GitHub repository
settings pointing at a real cluster. For local lab use, the manual
setup steps in this README achieve the same result.

---

## What This Module Covers

| Control | Tool | What It Mitigates |
|---|---|---|
| API gateway — route blocking | Kong (DB-less) | Admin panel, internal endpoints, API docs exposed |
| API gateway — rate limiting | Kong rate-limiting plugin | Brute-force PIN reset (3-digit = 1,000 combinations) |
| API gateway — request size limit | Kong request-size-limiting plugin | Large payload attacks |
| Security response headers | Kong response-transformer plugin | Clickjacking, MIME sniffing, server fingerprinting |
| TLS termination | cert-manager + Kong | Plaintext traffic interception |
| Network segmentation | Kubernetes NetworkPolicy | SSRF to host/metadata, lateral movement between tiers |
| Namespace isolation | Kubernetes namespaces | Blast radius containment |

---

## Architecture

```
Internet / Attacker
        │
        ▼  NodePort (HTTP :30080 / HTTPS :30443)
┌─────────────────────────────┐
│  Kong API Gateway           │  namespace: kong
│  - TLS termination          │
│  - Route allow/block rules  │
│  - Rate limiting            │
│  - Security headers         │
└─────────────┬───────────────┘
              │ ClusterIP (internal only)
              ▼
┌─────────────────────────────┐
│  VulnBank Flask App         │  namespace: vuln-bank
│  Port 5000                  │
└─────────────┬───────────────┘
              │ ClusterIP (NetworkPolicy restricted)
              ▼
┌─────────────────────────────┐
│  PostgreSQL                 │  namespace: vuln-bank-db
│  Port 5432                  │
└─────────────────────────────┘
```

Traffic can only flow downward through this diagram. The NetworkPolicies
enforce this at the kernel level, no pod can reach a tier above or
beside it.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Kubernetes cluster | Tested on k3s single-node. Minikube also works. |
| kubectl | Configured and pointing at your cluster |
| Helm 3 | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| 4 vCPU / 4 GiB RAM minimum | Full stack uses ~800 MB RAM |

**k3s users:** k3s stores its kubeconfig at a non-standard path.
Copy it to the standard location before running Helm or kubectl:

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
chmod 600 ~/.kube/config
```

---

## Setup

Work through the steps in order. Each step depends on the previous one.

### Step 1: Prepare the cluster

```bash
# Single-node clusters need the control-plane taint removed
# so workloads can schedule on the same node
kubectl taint nodes --all node-role.kubernetes.io/control-plane- 2>/dev/null || true

# Create all namespaces with labels
# Labels are required because NetworkPolicy selectors use them
kubectl apply -f manifests/namespaces.yaml

# Verify
kubectl get namespaces --show-labels | grep -E "vuln-bank|kong|cert-manager"
```

### Step 2: Install cert-manager

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml

# Wait for all three components to be ready
kubectl wait --for=condition=ready pod -l app=cert-manager    -n cert-manager --timeout=120s
kubectl wait --for=condition=ready pod -l app=cainjector      -n cert-manager --timeout=120s
kubectl wait --for=condition=ready pod -l app=webhook         -n cert-manager --timeout=120s

# Create the self-signed lab CA and ClusterIssuer
kubectl apply -f cert-manager/cluster-issuer.yaml

# Verify the CA certificate was issued
kubectl get certificate -n cert-manager
```

### Step 3: Deploy PostgreSQL

```bash
# Create the database credentials secret. Note: Change the password before use
kubectl create secret generic postgres-secret \
  --from-literal=username=postgres \
  --from-literal=password=ChangeMe2024! \
  -n vuln-bank-db

# Deploy PostgreSQL
kubectl apply -f manifests/postgres/postgres.yaml

# Verify it is running
kubectl get pods -n vuln-bank-db
kubectl logs -n vuln-bank-db -l app=postgres --tail=10
```

### Step 4: Build and deploy VulnBank

VulnBank must be built locally and imported into your cluster.
There is no pre-built image in a public registry, this is intentional
for a deliberately vulnerable application.

```bash
# Clone the app repo if you have not already
git clone https://github.com/Commando-X/vuln-bank.git
cd vuln-bank

# Build the image
docker build -t vuln-bank:v1.0 .

# Import into your cluster's container runtime
# k3s / containerd:
docker save vuln-bank:v1.0 | sudo ctr -n k8s.io images import -

# Verify the image is available to the cluster
sudo crictl images | grep vuln-bank

cd -
```

```bash
# Create the secret the app uses to connect to the database
# Must match the password set in Step 3
kubectl create secret generic vuln-bank-db-secret \
  --from-literal=username=postgres \
  --from-literal=password=ChangeMe2024! \
  -n vuln-bank

# Deploy the application
kubectl apply -f manifests/vuln-bank/app.yaml

# Watch the rollout
kubectl rollout status deployment/vuln-bank -n vuln-bank

# Confirm the app started and connected to the database
kubectl logs -n vuln-bank -l app=vuln-bank --tail=20
```

### Step 5: Deploy Kong API Gateway

```bash
helm repo add kong https://charts.konghq.com
helm repo update

# Apply the declarative config as a ConfigMap (idempotent and safe to re-run)
kubectl create configmap kong-config \
  --from-file=kong.yaml=kong/kong.yaml \
  -n kong \
  --dry-run=client -o yaml | kubectl apply -f -

# Install Kong in DB-less mode
helm install kong kong/ingress -n kong -f kong/values.yaml

# Wait for Kong to be ready
kubectl rollout status deployment/kong-gateway -n kong

# If Helm did not mount the ConfigMap automatically, patch it:
kubectl describe deployment kong-gateway -n kong | grep -A5 "Volumes:"
# If kong-config volume is missing, run these three commands:
kubectl patch deployment kong-gateway -n kong --type='json' \
  -p='[{"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"kong-config","configMap":{"name":"kong-config"}}}]'
kubectl patch deployment kong-gateway -n kong --type='json' \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"kong-config","mountPath":"/kong_dbless"}}]'
kubectl set env deployment/kong-gateway -n kong KONG_DECLARATIVE_CONFIG=/kong_dbless/kong.yaml

# Delete the ingress controller deployment if it was created,
# it will continuously overwrite declarative config with an empty state
kubectl delete deployment kong-controller -n kong --ignore-not-found

# Restart to pick up all changes
kubectl rollout restart deployment/kong-gateway -n kong
```

### Step 6: Apply NetworkPolicies

```bash
kubectl apply -f manifests/network-policies/vuln-bank-netpol.yaml
kubectl apply -f manifests/network-policies/postgres-netpol.yaml

# Verify policies are in place
kubectl get networkpolicies -n vuln-bank
kubectl get networkpolicies -n vuln-bank-db
```

### Step 7: Issue TLS certificate

```bash
kubectl apply -f manifests/tls/kong-tls-cert.yaml

# Wait for the certificate to be issued (Ready: True)
kubectl get certificate -n kong --watch
```

---

## Verification

### Discover the actual NodePorts

Kubernetes may assign different ports than those specified in
`values.yaml`. Always check the live service:

```bash
kubectl get svc kong-gateway-proxy -n kong
# Example output: 80:30598/TCP,443:31173/TCP
#                      ^^^^^         ^^^^^ use these ports

export NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[0].address}')
export HTTP_PORT=$(kubectl get svc kong-gateway-proxy -n kong \
  -o jsonpath='{.spec.ports[?(@.name=="kong-proxy")].nodePort}')
export HTTPS_PORT=$(kubectl get svc kong-gateway-proxy -n kong \
  -o jsonpath='{.spec.ports[?(@.name=="kong-proxy-tls")].nodePort}')

echo "HTTP:  http://${NODE_IP}:${HTTP_PORT}"
echo "HTTPS: https://${NODE_IP}:${HTTPS_PORT}"
```

### Check the app is reachable

```bash
curl -si http://${NODE_IP}:${HTTP_PORT}/login | head -5
# Expected: HTTP 200, HTML login page
```

### Verify blocked routes return 404 from Kong

These requests are terminated by Kong before ever reaching the app:

```bash
curl -si http://${NODE_IP}:${HTTP_PORT}/internal/secret
curl -si http://${NODE_IP}:${HTTP_PORT}/api/admin
curl -si http://${NODE_IP}:${HTTP_PORT}/api/docs
curl -si http://${NODE_IP}:${HTTP_PORT}/static/openapi.json
# Expected for all: HTTP 404 {"message":"Not found"}
```

### Verify rate limiting triggers

```bash
for i in $(seq 1 25); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://${NODE_IP}:${HTTP_PORT}/api/v1/auth \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"wrong"}'
done
# Expected: 200/401 for the first 20 requests, then 429
```

### Verify security headers and fingerprint suppression

```bash
curl -si http://${NODE_IP}:${HTTP_PORT}/login | grep -iE "server|x-powered|via|x-content|x-frame|referrer"
# Expected present:  X-Content-Type-Options, X-Frame-Options, Referrer-Policy
# Expected absent:   Server, X-Powered-By, Via
```

### Verify SSRF is blocked by NetworkPolicy

VulnBank has a SSRF vulnerability at `/upload_profile_picture_url`.
The egress NetworkPolicy blocks the outbound connection at the pod level:

```bash
curl -s -X POST http://${NODE_IP}:${HTTP_PORT}/upload_profile_picture_url \
  -H "Authorization: Bearer <your_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"image_url":"http://169.254.169.254/latest/meta-data/"}'
# Expected: connection timeout. The pod cannot reach the target
```

---

## Kong Configuration Notes

### Route priority

Kong matches routes by path specificity, longer paths win over shorter
ones. The blocked routes (`/internal`, `/api/admin`, `/api/docs`,
`/static/openapi.json`) are matched and terminated before the catch-all
`/` route ever sees the request. No Lua code required.

### Why `request-termination` and not `pre-function`

`request-termination` is a declarative, purpose-built plugin for
blocking routes. `pre-function` runs arbitrary Lua code inside Kong's
runtime and should only be used when no native plugin covers the
requirement. Using `pre-function` for path blocking introduces
unnecessary attack surface and makes config harder to audit.

### Why `controller.enabled: false`

The Kong Helm chart ships as a dual-mode chart, it can run as either
a pure DB-less gateway or as an ingress controller that watches
Kubernetes Ingress resources. When both modes are active simultaneously,
the controller has authority over the routing table and periodically
pushes its state to Kong, overwriting the declarative `kong.yaml`.
With no Ingress resources deployed, this results in an empty routing
table and universal 404s. Setting `controller.enabled: false` locks
routing exclusively to `kong.yaml`.

### Why `externalTrafficPolicy: Local`

With the default `Cluster` policy, Kubernetes performs SNAT on NodePort
traffic, it rewrites the source IP to the node's IP before the packet
reaches the Kong pod. Kong then sees the same node IP for every client,
making IP-based rate limiting useless and trivially bypassable with a
spoofed `X-Real-IP` header.

`Local` policy bypasses SNAT so the real client IP arrives at Kong
directly. Combined with removing `trusted_ips` from the Kong config,
rate limiting now keys on the actual TCP source IP which cannot be
spoofed at the HTTP layer.

**Trade-off:** `Local` routes traffic only to nodes that have a Kong
pod running. On a single-node cluster this has no effect. On a
multi-node cluster, ensure Kong pods are spread across nodes with a
`DaemonSet` or `podAntiAffinity` rules.

---

## Known Issues and Lessons Learned

Real issues encountered during development, documented so you do not
have to rediscover them.

| Issue | Symptom | Fix |
|---|---|---|
| `_transform: true` in kong.yaml | `deck file validate` fails | Remove it, not valid in Kong 3.0 schema |
| Duplicate `response-transformer` plugin | Kong fails to load config, all routes 404 | Merge into one plugin block with both `add` and `remove` under the same `config` |
| Ingress controller overwriting routes | Routes work briefly after restart then break | Set `controller.enabled: false` at both chart levels; delete `kong-controller` deployment |
| Helm cannot reach cluster | `connection refused at localhost:8080` | k3s kubeconfig is at `/etc/rancher/k3s/k3s.yaml`, copy to `~/.kube/config` and `chmod 600` |
| Rate limit bypass via header spoofing | Attacker rotates `X-Real-IP` to bypass limits | Remove `trusted_ips`; set `externalTrafficPolicy: Local` to prevent SNAT |
| ConfigMap not mounted automatically | Kong starts but routes are empty | Patch the deployment manually to add volume and volumeMount (see Step 5) |

---

## Vuln-to-Control Mapping

Format used for compensating control documentation in financial sector
security audits.

| Vulnerability | Control Applied | Residual Risk |
|---|---|---|
| No rate limiting on auth endpoints | Kong rate-limiting: 20 req/min on auth routes | Medium. Underlying 3-digit PIN still weak |
| Admin panel exposed | `/api/admin` → 404 at Kong edge | Low |
| API docs / Swagger exposed | `/api/docs`, `/static/openapi.json` → 404 at Kong edge | Low |
| Internal metadata endpoints exposed | `/internal/*` → 404 at Kong edge | Low |
| SSRF via URL-based profile image import | Egress NetworkPolicy blocks outbound from app pod | Low. Dual control with Kong route blocking |
| No TLS on traffic | TLS termination at Kong via cert-manager | Low. Lab CA only |
| Server version fingerprinting | `Server` and `Via` headers stripped by Kong | Low |
| XSS / Clickjacking | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` injected | Medium. No WAF |
| SQL injection in login | No code-level fix (intentional) | HIGH. Residual |
| Race conditions in transfers | No control applied in this phase | HIGH. Residual |

---

## Relationship to the CI/CD Pipeline

The existing pipeline in this repo tests the **code and container** before
deployment. This module hardens the **infrastructure** the app runs inside.
They address different layers and are both necessary:

```
  Code commit
      │
      ▼
  ┌─────────────────────────────────────────────┐
  │  CI/CD Pipeline: existing devsecops.yml     │
  │  ├── SAST        SonarQube                  │
  │  ├── SCA         Snyk                       │
  │  ├── Container   Trivy                      │
  │  ├── IaC scan    Checkov                    │
  │  └── DAST        OWASP ZAP                  │
  └─────────────────────────────────────────────┘
      │
      ▼
  Deployment target (choose one)
  ├── deploy/deploy.sh    →  EC2, bare Docker      (existing)
  └── This module         →  Kubernetes cluster    (this PR)
      │
      ▼
  ┌─────────────────────────────────────────────┐
  │  Runtime Infrastructure: this module        │
  │  ├── Kong API Gateway                       │
  │  ├── NetworkPolicies                        │
  │  ├── Namespace isolation                    │
  │  └── TLS (cert-manager)                     │
  └─────────────────────────────────────────────┘
```

The two deployment targets are independent. The K8s module is not a
replacement for `deploy.sh`, it is a different runtime environment
designed for practising infrastructure security controls. See the
**Deployment Model** section at the top of this file for details on
how this would integrate into an automated pipeline.

---

## What Comes Next (Phase 2)

Controls not included here that extend this module naturally:

- **Falco**: runtime anomaly detection (shell spawning in containers,
  unexpected outbound connections, suspicious file access)
- **Kyverno**: admission control policies (deny root pods, require
  resource limits, restrict image registries)
- **Vault**: dynamic secret injection to replace Kubernetes Secrets

---

## Contributing

If you extend this module (Phase 2 controls, additional Kong plugins,
Kyverno policies), open a PR against this repo following the same
structure. Each addition should include the manifest files and a new
row in the vuln-to-control mapping table above.

---

## Disclaimer

This module is designed for use with VulnBank, a **deliberately
vulnerable application**. Do not deploy VulnBank or this configuration
on public networks or with real data.
