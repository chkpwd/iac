
import * as pulumi from "@pulumi/pulumi";
import * as docker from "@pulumi/docker";
import { Input, interpolate } from "@pulumi/pulumi";
import { ContainerLabel } from "@pulumi/docker/types/input";

export const TZ = "America/New_York";

export function mountDockerSocket(
  readOnly = true
): docker.types.input.ContainerMount {
  return {
    type: "bind",
    target: "/var/run/docker.sock",
    source: "/var/run/docker.sock",
    readOnly,
  };
}

export function mountAppDataVolume(appdataPath: string, containerPath: string) {
  return {
    containerPath,
    hostPath: `/mnt/user/appdata/${appdataPath}`,
  };
}

export function appDataVolume(appdataPath: string, containerPath: string) {
  return {
    containerPath,
    hostPath: `/mnt/user/appdata/${appdataPath}`,
  };
}

interface LabelOptions {
  /** host.example.com */
  subdomain?: string;
  path?: string;
  icon?: string;
  middlewares?: Array<"auth@file" | "sonarrHeader@file" | string>;
  /** For traefik */
  network?: Input<string>;
  /** For watchtower */
  autoupdate?: boolean;
}

export function objectToArray(
  object: Record<string, Input<string>>
): ContainerLabel[] {
  return Object.entries(object).map(([label, value]) => ({
    label,
    value,
  }));
}

export function objectToEnvs(
  input: Record<string, pulumi.Input<string> | boolean> = {}
) {
  input = {
    TZ,
    ...input,
  };

  return Object.entries(input).map(
    ([key, value]) =>
      interpolate`${key}=${
        typeof value === "boolean" ? value.toString() : value
      }`
  );
}