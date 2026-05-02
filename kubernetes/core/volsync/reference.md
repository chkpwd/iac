hi# Kopia Policy `repositoryConfig` Reference

Generated from Kopia **v0.22.3** (VolSync `ghcr.io/perfectra1n/volsync:v0.17.11`).

Valid JSON fields for `policyConfig.repositoryConfig` in a VolSync `ReplicationSource` or `ReplicationDestination`.

> `retain`, `compression`, and `parallelism` are managed by the VolSync spec — set them there, not here.

---

## Full Schema

```json
{
  "retention": {
    "keepLatest": 10,
    "keepHourly": 48,
    "keepDaily": 7,
    "keepWeekly": 4,
    "keepMonthly": 24,
    "keepAnnual": 3,
    "ignoreIdenticalSnapshots": false
  },
  "files": {
    "ignore": ["lost+found/"],
    "ignoreDotFiles": [".kopiaignore"],
    "ignoreCacheDirs": true,
    "oneFileSystem": true
  },
  "errorHandling": {
    "ignoreFileErrors": false,
    "ignoreDirectoryErrors": false,
    "ignoreUnknownTypes": true
  },
  "scheduling": {
    "runMissed": true
  },
  "compression": {
    "compressorName": "zstd-fastest"
  },
  "metadataCompression": {
    "compressorName": "zstd-fastest"
  },
  "splitter": {},
  "actions": {},
  "osSnapshots": {
    "volumeShadowCopy": {
      "enable": 0
    }
  },
  "logging": {
    "directories": {
      "snapshotted": 5,
      "ignored": 5
    },
    "entries": {
      "snapshotted": 0,
      "ignored": 5,
      "cacheHit": 0,
      "cacheMiss": 0
    }
  },
  "upload": {
    "maxParallelSnapshots": 1,
    "parallelUploadAboveSize": 2147483648
  }
}
```

---

## Field Reference

### `retention`

> Prefer the VolSync `retain` spec field for `keepLatest/Hourly/Daily/Weekly/Monthly` — duplicating them here will conflict.

| Field                      | Type | Default | Description                                             |
| -------------------------- | ---- | ------- | ------------------------------------------------------- |
| `keepLatest`               | int  | 10      | Keep N most recent snapshots unconditionally            |
| `keepHourly`               | int  | 48      | Keep N most recent per hour                             |
| `keepDaily`                | int  | 7       | Keep N most recent per day                              |
| `keepWeekly`               | int  | 4       | Keep N most recent per week                             |
| `keepMonthly`              | int  | 24      | Keep N most recent per month                            |
| `keepAnnual`               | int  | 3       | Keep N most recent per year                             |
| `ignoreIdenticalSnapshots` | bool | false   | Skip snapshot if contents are identical to the previous |

---

### `files`

| Field             | Type     | Default            | Description                                                |
| ----------------- | -------- | ------------------ | ---------------------------------------------------------- |
| `ignore`          | []string | `[]`               | Glob patterns to exclude (e.g. `"lost+found/"`, `"*.tmp"`) |
| `ignoreDotFiles`  | []string | `[".kopiaignore"]` | Filenames treated as per-directory ignore rule files       |
| `ignoreCacheDirs` | bool     | false              | Skip directories tagged with CACHEDIR.TAG                  |
| `oneFileSystem`   | bool     | false              | Don't cross filesystem boundaries (`find -xdev`)           |

> `dotFiles: "include"` is **not** a valid field — it's silently ignored. Use `ignoreDotFiles` instead.

---

### `errorHandling`

| Field                   | Type | Default | Description                           |
| ----------------------- | ---- | ------- | ------------------------------------- |
| `ignoreFileErrors`      | bool | false   | Continue on file read errors          |
| `ignoreDirectoryErrors` | bool | false   | Continue on directory read errors     |
| `ignoreUnknownTypes`    | bool | true    | Ignore unknown filesystem entry types |

---

### `compression`

> Also set by the VolSync `compression` spec field — only override here if the spec doesn't expose what you need.

| Field            | Type   | Description           |
| ---------------- | ------ | --------------------- |
| `compressorName` | string | Compression algorithm |

Valid values: `none`, `lz4`, `zstd`, `zstd-fastest`, `zstd-better-compression`, `zstd-best-compression`, `s2-default`, `s2-better`, `s2-parallel-4`, `s2-parallel-8`, `gzip`, `gzip-best-speed`, `gzip-best-compression`, `pgzip`, `pgzip-best-speed`, `pgzip-best-compression`, `deflate-best-speed`, `deflate-default`, `deflate-best-compression`

---

### `metadataCompression`

Applied to manifests and index objects. Independent of content compression. Same valid values as `compression`.

| Field            | Type   | Default        |
| ---------------- | ------ | -------------- |
| `compressorName` | string | `zstd-fastest` |

---

### `scheduling`

| Field       | Type | Default | Description                                  |
| ----------- | ---- | ------- | -------------------------------------------- |
| `runMissed` | bool | true    | Run a snapshot if a scheduled one was missed |

---

### `upload`

| Field                     | Type  | Default    | Description                                         |
| ------------------------- | ----- | ---------- | --------------------------------------------------- |
| `maxParallelSnapshots`    | int   | 1          | Max concurrent snapshots (KopiaUI/server mode only) |
| `parallelUploadAboveSize` | int64 | 2147483648 | Parallel upload threshold in bytes (default 2 GiB)  |

---

### `logging`

Log detail level per entry type — `0` = disabled, higher = more verbose.

```json
"logging": {
  "directories": { "snapshotted": 5, "ignored": 5 },
  "entries":     { "snapshotted": 0, "ignored": 5, "cacheHit": 0, "cacheMiss": 0 }
}
```

---

### `splitter`

Content-defined chunking. Leave as `{}` to use repository defaults.

---

### `actions`

Pre/post snapshot hooks. Leave as `{}` unless needed — prefer VolSync's `actions.beforeSnapshot` / `actions.afterSnapshot` instead.

---

### `osSnapshots` (Windows only)

VSS settings. Not applicable in Linux containers.

```json
"osSnapshots": { "volumeShadowCopy": { "enable": 0 } }
```

---

## Minimal Config

Let VolSync handle retention and compression; use `repositoryConfig` only for what the spec doesn't expose:

```json
{
  "files": {
    "ignore": ["lost+found/"],
    "ignoreCacheDirs": true
  },
  "errorHandling": {
    "ignoreUnknownTypes": true
  },
  "metadataCompression": {
    "compressorName": "zstd-fastest"
  }
}
```
