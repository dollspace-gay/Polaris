# Polaris Helm chart

Kubernetes install posture for Polaris. The chart provisions the
`polaris-backend` Deployment, an Ingress (cert-manager-friendly), and
optional Bitnami `postgresql` + `redis` and nats-io `nats` sub-charts.

For single-host (compose) installs see
[`docs/ops/quick-start.md`](../../docs/ops/quick-start.md). For
upgrades see [`docs/ops/upgrade.md`](../../docs/ops/upgrade.md).

## Prerequisites

- Kubernetes ≥ 1.27 (see `Chart.yaml` `kubeVersion`).
- Helm ≥ 3.14 (OCI sub-chart support is mandatory; the chart pulls
  Bitnami sub-charts from `oci://registry-1.docker.io/bitnamicharts`).
- An ingress controller (default values target `nginx`) and
  `cert-manager` with a working ClusterIssuer, OR your own TLS
  termination story.
- DNS pointing at the ingress controller's external address.

## Image

The chart references the published multi-arch image:

```yaml
polaris:
  image:
    repository: ghcr.io/dollspace-gay/polaris-backend
    tag: "0.1.0-bluesky"        # or `latest`, or a pinned v* tag
    pullPolicy: IfNotPresent
```

The image is produced by the
[`publish-image`](../../.github/workflows/publish-image.yml) workflow
on every push to `main` (yielding `:latest` + `:main-<sha>`) and on
every `v*` git tag (yielding `:vX.Y.Z`). For production, pin a
release tag — see "Upgrades" below.

The default `polaris.profile: bluesky` in `values.yaml.example`
matches the `0.1.0-bluesky` tag suffix and the Dockerfile.bluesky-
profile image. Operators on the labeler profile should override
`polaris.profile: labeler` and use the unsuffixed image tag.

## Secrets

Polaris reads every sensitive value from a Kubernetes Secret named
`polaris-secrets` (the name is wired in `values.yaml.example` as
`polaris.envFromSecret`). The chart deliberately does **not** ship a
templated Secret manifest — committing one would defeat the point.

You have three reasonable options, all documented inline in
[`templates/secret.yaml.example`](templates/secret.yaml.example):

### Option A — generate locally with polaris-setup, materialise as a Secret

`polaris-setup` writes a `.env` file with freshly-rolled cookie key
and Postgres password. You can run it once locally, then translate
the file into a Secret:

```sh
# Generate the secrets in a temp dir
polaris-setup --hostname polaris.example.com --dir ./tmp-setup --non-interactive
# Hand-translate to a Secret (file maps key=value lines to literals)
kubectl -n polaris create secret generic polaris-secrets \
  --from-env-file=./tmp-setup/.env
rm -rf ./tmp-setup
```

This is convenient for development clusters. **Do not** check
`./tmp-setup/.env` into git — `polaris-setup` chmods it to 0600 and
the repo `.gitignore` already excludes `.env`, but treat it as
ephemeral regardless.

The OAuth `client-metadata.json` the script also writes is consumed
the same way it is in the compose stack: mount it into the pod at the
`POLARIS_ATPROTO_CLIENT_METADATA` path (default
`/etc/polaris/client_metadata.json`). The simplest pattern is a
ConfigMap from the generated file:

```sh
kubectl -n polaris create configmap polaris-oauth \
  --from-file=client_metadata.json=./tmp-setup/client-metadata.json
```

Then mount the ConfigMap into the Deployment via a values override.

### Option B — kubectl create secret (one-liner, dev clusters)

```sh
POLARIS_COOKIE_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
REDIS_PASSWORD=$(openssl rand -hex 24)

kubectl -n polaris create secret generic polaris-secrets \
  --from-literal=POLARIS_COOKIE_KEY="$POLARIS_COOKIE_KEY" \
  --from-literal=POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  --from-literal=POSTGRES_ADMIN_PASSWORD="$POSTGRES_PASSWORD" \
  --from-literal=REDIS_PASSWORD="$REDIS_PASSWORD" \
  --from-literal=DATABASE_URL="postgres://polaris:${POSTGRES_PASSWORD}@polaris-postgresql:5432/polaris" \
  --from-literal=POLARIS_LABELER_SIGNING_KEY_MODE="cloud-kms-oracle" \
  --from-literal=POLARIS_LABELER_SIGNING_KEY_KMS_PROVIDER="aws" \
  --from-literal=POLARIS_LABELER_SIGNING_KEY_KMS_KEY_ID="<arn>" \
  --from-literal=POLARIS_LABELER_SIGNING_KEY_KMS_REGION="us-east-1"
```

The full list of literals is in
[`templates/secret.yaml.example`](templates/secret.yaml.example).

### Option C — external-secrets-operator or SealedSecrets (production)

The chart references `polaris-secrets` by name. How that Secret comes
into existence is opaque to the chart. For production, point an
`ExternalSecret` resource at your secret store (AWS Secrets Manager,
GCP Secret Manager, HashiCorp Vault) or commit a SealedSecret. See
`templates/secret.yaml.example` for both flows.

Bitnami sub-charts read their own credentials from the same Secret
via `existingSecret`/`existingSecretPasswordKey` in
`values.yaml.example`, so you do not need to maintain separate
postgresql/redis Secrets.

## Signing-key custody on Kubernetes

The `polaris.profile: bluesky` default refuses `file-plain` key
custody at boot — production Kubernetes installs are expected to use
`cloud-kms-oracle` (AWS KMS today, GCP/Azure stubbed) or
`os-keychain` via a sidecar pattern. Configure via:

```yaml
# inside polaris-secrets
POLARIS_LABELER_SIGNING_KEY_MODE=cloud-kms-oracle
POLARIS_LABELER_SIGNING_KEY_KMS_PROVIDER=aws
POLARIS_LABELER_SIGNING_KEY_KMS_KEY_ID=arn:aws:kms:us-east-1:...:key/...
POLARIS_LABELER_SIGNING_KEY_KMS_REGION=us-east-1
```

If you are on the labeler profile (`polaris.profile: labeler`),
`file-plain` is permitted — mount the key file via a CSI driver
(secrets-store, vault-csi) into the path specified by
`POLARIS_LABELER_SIGNING_KEY_PATH`.

See `docs/ops/key-custody.md` for the rotation procedure.

## Install

```sh
# 1. cp values.yaml.example values.yaml; edit polaris.hostname, image.tag, ingress.
cp values.yaml.example values.yaml
$EDITOR values.yaml

# 2. Create the Secret (Option A/B/C above).

# 3. Pull sub-chart dependencies.
helm dependency update

# 4. Install.
helm install polaris . -f values.yaml -n polaris --create-namespace
```

Verify:

```sh
kubectl -n polaris rollout status deploy/polaris
kubectl -n polaris get ingress
curl -fsS https://<polaris.hostname>/healthz
```

Then open `https://<polaris.hostname>/` in the browser and walk the
in-app setup wizard exactly as documented in
[`quick-start.md`](../../docs/ops/quick-start.md) §3–5.

## Upgrades

Bump the image tag in `values.yaml`:

```yaml
polaris:
  image:
    tag: "vX.Y.Z"   # or a sha256:<digest> for stricter pinning
```

Then:

```sh
helm upgrade polaris . -f values.yaml -n polaris
kubectl -n polaris rollout status deploy/polaris
```

Polaris auto-runs `sqlx` migrations on boot. The same
forward-only-migration discipline documented in
[`docs/ops/upgrade.md`](../../docs/ops/upgrade.md) applies — back up
Postgres before any upgrade whose CHANGELOG entry is under
**Changed** or **Removed**.

## Replica count and rolling updates

The default `polaris.replicaCount: 2` is the minimum for a rolling
update without a brief downtime window. The backend is stateless
(state lives in Postgres + Redis + NATS) so horizontal scale is
trivial; bump `replicaCount` as load demands.

## Chart versioning

The Helm chart version and the Polaris `appVersion` in `Chart.yaml`
are intentionally decoupled. Bumping the chart's structure (a new
template, a new sub-chart, a changed default) is a chart-version
event; bumping the polaris-backend image is an `appVersion` event.
The Polaris workspace itself is at the version pinned in
[`../../Cargo.toml`](../../Cargo.toml).
