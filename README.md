# Configure relation between apps in kubernetes
![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=for-the-badge&logo=kubernetes&logoColor=white)

[![Apache licensed](https://img.shields.io/badge/license-Apache-blue.svg)](./LICENSE)
[![ci](https://github.com/sebt3/kuberest/actions/workflows/ci.yml/badge.svg)](https://github.com/sebt3/kuberest/actions/workflows/ci.yml)
[![docker image](https://img.shields.io/docker/pulls/sebt3/kuberest.svg)](
https://hub.docker.com/r/sebt3/kuberest/tags/)


This repository contains a custom Kubernetes controller that can create/update/delete REST object on RESTfull api-endpoint.
The main goal is to not write a post-install Job ever again for my applications deployments on Kubernetes.

## Use cases

- Configure OpenID applications in most ID-provider to provide seamless integration between applications
- Configure your own forge projects
- pretty much any relationship in between applications installed in kubernetes that could be configured by a REST-api (that surprisingly a lot)

## Installation

### CRD
Apply the CRD from [cached file](yaml/crd.yaml):

```sh
kubectl apply -f yaml/crd.yaml
```

### Controller

Install the controller via `helm` by setting your preferred settings. For defaults:

```sh
helm template charts/kuberest | kubectl apply -f -
kubectl wait --for=condition=available deploy/kuberest --timeout=30s
kubectl port-forward service/kuberest 8080:80
```
### Tenant aware

The controller can either function per-namespace (refuse to read secrets from other namespace mostly) or behave globally. The default behaviour is to limit to current namespace, to activate, set the environement variable MULTI_TENANT to false.

## Usage

### basic structure of a RestEndpoint object

### Running flow

### Examples

### Abuses

Doing like in the following is not realy recommanded, there's probably