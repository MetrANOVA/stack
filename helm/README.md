# Helm Chart Layout

This directory contains Helm charts for the MetraNova stack.

- `charts/`: local component chart sources (subcharts used by the umbrella chart)
- `metranova/`: umbrella chart that composes the stack
- `metranova/charts/`: generated dependency tarballs created by `helm dependency build`/`helm dependency update`

For umbrella chart installation and upgrade instructions, see:

- [metranova/README.md](metranova/README.md)
