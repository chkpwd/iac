Helm chart **v1.7.2** from `oci://mirror.gcr.io/envoyproxy/gateway-helm`.

---

## Helm values

| Value                                                      | Setting            | Effect                                                                               |
| ---------------------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------ |
| `config.envoyGateway.extensionApis.enableBackend`          | `true`             | Enables the Backend extension API for routing to non-Service backends                |
| `config.envoyGateway.extensionApis.enableEnvoyPatchPolicy` | `true`             | Enables EnvoyPatchPolicy for low-level Envoy config patches (e.g. Zstd compression)  |
| `config.envoyGateway.provider.type`                        | `Kubernetes`       | Standard Kubernetes provider                                                         |
| `config.envoyGateway.provider.kubernetes.deploy.type`      | `GatewayNamespace` | Envoy proxy pods deploy in the Gateway's namespace, giving predictable Service names |
