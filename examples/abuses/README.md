# Warning

Examples in this directory are only here to demo some of the operator features.

This directory is named "abuses" for a reason: kuberest have never been designed to do theses things. It is just possible by its featureset.

There is probably a better operator out there better suited for the task than kuberest ([Secret Generator](https://github.com/mittwald/kubernetes-secret-generator), [External Secret](https://external-secrets.io/latest/), [reflector](https://github.com/emberstack/kubernetes-reflector)...) do not use kuberest if your use-case is only any of these but use a better suited tool :)

## secret-copy

For this one to work, multi-tenancy have to be disabled at the operator level.

## k8s-system-pod

Seriously don't do this. This is just an mTLS demo, and the api-server is an mTLS enabled API we all knows. Having your admin mtls keys within the cluster is a huge security issue. Writes on the api-server is completly untested


