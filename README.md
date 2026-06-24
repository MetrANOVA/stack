# MetrANOVA Stack
The MetrANOVA Stack brings together collectors, the message bus, pipelines and data stores for specific data sets. These are available for:

- **Docker Compose** - We provide a set of utilites that will allow you to select components and run various stack in docker compose
- **Kubernetes** - We provide a set of helm charts that bring up all the components needed for a given stack in a kubernetes environment.


## Docker Compose

Documentation on bringing up individual MetrANOVA stacks in docker can be find below:

- [Flow Stack](flow/README.md)


## Helm Charts

Published Helm repository:

- https://metranova.github.io/stack

Quick start:

```bash
helm repo add metranova https://metranova.github.io/stack
helm repo update
helm search repo metranova --versions
```

Production install (published repo):

```bash
helm upgrade --install metranova metranova/metranova \
	--namespace metranova \
	--create-namespace
```

Development install (local checkout):

```bash
git clone https://github.com/MetrANOVA/stack.git
cd stack
git checkout main
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
helm dependency build helm/metranova
helm upgrade --install metranova ./helm/metranova \
	--namespace metranova \
	--create-namespace
```

Detailed values and secrets guidance:

- [helm/metranova/README.md](helm/metranova/README.md)
