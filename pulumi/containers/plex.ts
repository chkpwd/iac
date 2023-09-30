import * as docker from "@pulumi/docker";
import { TZ } from "../docker";

const name = "plex";

export const container = new docker.Container(
  name,
  {
    image: "lscr.io/linuxserver/plex",
    name: name,
    restart: "always",
    volumes: [
        {
            hostPath: "/tmp/plex",
            containerPath: "/config"
        },
        {
            hostPath: "/tmp/media",
            containerPath: "/data"
        }
    ],
    envs: [`TZ=${TZ}`, "VERSION=docker"],
    ports: [
      {
        internal: 32400,
        external: 32400,
      },
    ],

  },
);

container.name