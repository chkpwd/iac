"""
ExternalSecret renderer — Bitwarden-backed secrets.

Covers the dominant pattern across the cluster: one or more Bitwarden item
extracts, fanned out into a flat `template.data` map of secret keys. Designed
as the source of truth for ~33 of the 39 ExternalSecret YAML files in the
repo. Edge cases (rewrite, ClusterGenerator, spec.data[] direct refs, template
pipeline functions like `b64dec`) are intentionally NOT supported; those apps
keep hand-written YAML.

Usage:

    import schemas.external_secret as es

    spec = es.ExternalSecretSpec {
        name = "bazarr"
        bitwardenKey = "infra-media-secrets"
        template = {
            "BAZARR_API_KEY" = "bazarr_api_key"   # → "{{ .bazarr_api_key }}"
        }
    }
    es.renderExternalSecret(spec)

Multi-extract (e.g. jellyplex-watched merging Jellyfin + Plex secrets):

    spec = es.ExternalSecretSpec {
        name = "jellyplex-watched"
        extracts = ["jellyfin", "plex"]
        template = {
            "JELLYFIN_TOKEN" = "jellyfin_api_key"
            "PLEX_TOKEN" = "plex_api_key"
        }
    }

Constants and file-style multiline values:

    spec = es.ExternalSecretSpec {
        name = "volsync-kopia"
        bitwardenKey = "volsync-secrets"
        template = {
            "KOPIA_PASSWORD" = "kopia_password"                  # templated
            "KOPIA_REPOSITORY" = es.Raw("filesystem:///mnt/repo") # literal
            "config.json" = es.Multiline('''                      # block scalar
                {
                  "key": "{{ .my_field }}"
                }
            ''')
        }
    }
"""

# Schemas for tagged template values. Plain `str` values are auto-wrapped
# as `"{{ .<value> }}"`. Use Raw/Multiline helpers to opt out.

schema RawValue:
    """A constant string emitted verbatim into template.data."""
    value: str

schema MultilineValue:
    """A multi-line file body embedded into template.data as a YAML block.
    May contain Go template expressions which the controller will render."""
    value: str

# Helper constructors — call them like functions: Raw("..."), Multiline("...").
Raw = lambda s: str -> RawValue { RawValue {value = s} }
Multiline = lambda s: str -> MultilineValue { MultilineValue {value = s} }

schema ExternalSecretSpec:
    """A Bitwarden-backed ExternalSecret.

    Either `bitwardenKey` (single extract — most common) or `extracts`
    (list of N keys, merged in order) must be set. If both, `extracts` wins.
    """

    # Identity ------------------------------------------------------------
    name: str
    namespace?: str           # optional; ES is normally namespaced by Kustomization

    # Target Secret -------------------------------------------------------
    # `target.name`. Defaults to `name`. Override when the rendered Secret
    # needs a different name (e.g. `<app>-config`, `<app>-secret`).
    targetName?: str

    # Sync behavior -------------------------------------------------------
    refreshInterval: str = "3h"
    creationPolicy?: str       # "Owner" | "Merge" | "None" | "Orphan" — usually unset

    # Bitwarden source(s) -------------------------------------------------
    # Single-key shortcut. Equivalent to `extracts = [bitwardenKey]`.
    bitwardenKey?: str
    # Multi-key (in order). Each entry becomes one `dataFrom[].extract.key`.
    extracts?: [str]

    # Output Secret keys --------------------------------------------------
    # Map of resulting Secret key → value. Values may be:
    #   - `str` (bare): wrapped as `"{{ .<value> }}"` (the dominant pattern).
    #   - `Raw(str)`:   literal constant, no Go template wrapping.
    #   - `Multiline(str)`: rendered as a YAML block scalar (preserves newlines).
    template: {str: str | RawValue | MultilineValue}

    check:
        bitwardenKey or extracts, "must set bitwardenKey or extracts"

# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

# Convert one template-data value to its YAML-emitted form.
#   - bare str  -> "{{ .<value> }}"   (Go template field reference)
#   - RawValue  -> v.value             (verbatim)
#   - MultilineValue -> v.value        (verbatim; YAML encoder picks block style)
# KCL lambdas are single expressions and there's no isinstance(); we discriminate
# by checking for the schema's `value` attribute via typeof().
_renderTemplateValue = lambda v: str | RawValue | MultilineValue -> str {
    typeof(v) == "str" and "{{ .${v} }}" or v.value
}

renderExternalSecret = lambda es: ExternalSecretSpec -> {str:any} {
    _extracts = es.extracts if es.extracts else [es.bitwardenKey]
    _targetName = es.targetName or es.name
    _data = {k: _renderTemplateValue(v) for k, v in es.template}

    _metadata = {"name" = es.name} | ({"namespace" = es.namespace} if es.namespace else {})

    _target = {
        "name" = _targetName
        "template" = {
            "engineVersion" = "v2"
            "data" = _data
        }
    } | ({"creationPolicy" = es.creationPolicy} if es.creationPolicy else {})

    {
        "apiVersion" = "external-secrets.io/v1"
        "kind" = "ExternalSecret"
        "metadata" = _metadata
        "spec" = {
            "refreshInterval" = es.refreshInterval
            "secretStoreRef" = {
                "name" = "bitwarden-secrets-manager"
                "kind" = "ClusterSecretStore"
            }
            "target" = _target
            "dataFrom" = [{"extract" = {"key" = k}} for k in _extracts]
        }
    }
}
