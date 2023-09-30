import * as pulumi from "@pulumi/pulumi";
import * as vultr from "@ediri/vultr";
import * as k8s from "@pulumi/kubernetes";

let vke = new vultr.Kubernetes("vke", {
    region: "fra",
    version: "v1.28.2+1",
    label: "pulumi-vultr",
    nodePools: {
        nodeQuantity: 1,
        plan: "vc2-2c-4gb",
        label: "pulumi-vultr-nodepool",
    },
})

export const kubeconfig = vke.kubeConfig;
const kubernetes_provider = new k8s.Provider('kubernetes', {
    kubeconfig, // Equals to kubeconfig: kubeconfig since its defined with the same name
})

const nginx_ingress = new k8s.helm.v3.Chart('nginx-ingress', {
    chart: "nginx-ingress",
    version: "1.24.4",
    fetchOpts:{
        repo: "https://charts.helm.sh/stable",
    },
},
{
    provider: kubernetes_provider
}
)

export const public_ip = vke.ip