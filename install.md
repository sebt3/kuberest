---
layout: page
title: Installation
permalink: /install/
---
## Installation

(TL;DR: `kubectl apply -k github.com/sebt3/kuberest//deploy`)

Since this is a kubernetes operator, the installations steps are:
- first the CustomResourceDefinition
- then the operator controlling the ressources

Feel free to pick any of the installtions options for both.

### CRD


#### kubectl

```sh
kubectl apply -f deploy/crd/crd.yaml
```
#### kustomize

```sh
kubectl apply -k github.com/sebt3/kuberest//deploy/crd
```

### Operator

#### kubectl

```sh
helm template charts/kuberest | kubectl apply -f -
kubectl wait --for=condition=available deploy/kuberest --timeout=30s
```

#### kustomize

```sh
kubectl apply -k github.com/sebt3/kuberest//deploy/operator
```

#### helm

```sh
helm repo add kuberest https://sebt3.github.io/kuberest/
kubectl create ns kuberest
helm install kuberest/kuberest kuberest --namespace kuberest
```
