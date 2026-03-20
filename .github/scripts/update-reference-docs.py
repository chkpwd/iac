#!/usr/bin/env python3
"""
Update kubernetes component reference.md files using GitHub Models.
Reads current config files + reference.md, asks the model to reflect
any meaningful changes, writes back only if the content actually changed.
"""

import os
import sys
import textwrap
from pathlib import Path
from openai import OpenAI

REPO_ROOT = Path(__file__).parents[2]
CORE = REPO_ROOT / "kubernetes" / "core"

# Components to process: (directory, display name, config globs)
COMPONENTS = [
    (
        "cilium",
        "Cilium",
        ["values.yml", "pools.yml", "policy.yml", "helm-release.yml"],
    ),
    (
        "coredns",
        "CoreDNS",
        ["values.yml", "helm-release.yml"],
    ),
    (
        "flux-instance",
        "Flux Instance",
        ["values.yml", "helm-release.yml", "components/kustomization.yml"],
    ),
    (
        "gateway-api",
        "Gateway API",
        ["flux-kustomization.yml", "certificate.yml", "private-class.yml", "public-class.yml", "redirect-route.yml"],
    ),
    (
        "prometheus",
        "Prometheus",
        ["helm-release.yml", "alert-manager-config.yml"],
    ),
    (
        "rook-ceph",
        "Rook-Ceph",
        ["helm-release.yml", "cluster/helm-release.yml"],
    ),
    (
        "spegel",
        "Spegel",
        ["values.yml", "helm-release.yml"],
    ),
]

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a technical documentation assistant maintaining reference docs for a personal Kubernetes homelab cluster.
    The docs are written in a terse, direct style: tables for field-level detail, minimal prose, no filler phrases.
    Descriptions are short fragments, not full sentences. Bold is used sparingly.
    The audience is the author themselves — technically fluent, no hand-holding needed.

    When updating a reference doc:
    - Only change sections where the config has actually changed (new fields, removed fields, changed values, new behaviour).
    - Preserve all existing content that is still accurate — do not rewrite for style or completeness.
    - Do not add sections that weren't there before unless a genuinely new config area warrants it.
    - Do not add commentary about what you changed — just return the updated doc.
    - Return only the raw markdown content of the updated reference.md, nothing else.
    - If nothing meaningful has changed, return the existing doc unchanged.
""")

def load_configs(component_dir: Path, globs: list[str]) -> str:
    parts = []
    for pattern in globs:
        path = component_dir / pattern
        if path.exists():
            parts.append(f"### {path.relative_to(REPO_ROOT)}\n\n```yaml\n{path.read_text()}\n```")
        else:
            # try glob expansion for wildcards
            for match in sorted(component_dir.glob(pattern)):
                parts.append(f"### {match.relative_to(REPO_ROOT)}\n\n```yaml\n{match.read_text()}\n```")
    return "\n\n".join(parts)

def update_component(client: OpenAI, slug: str, name: str, globs: list[str]) -> bool:
    component_dir = CORE / slug
    reference_path = component_dir / "reference.md"

    if not reference_path.exists():
        print(f"  [skip] {name}: no reference.md found at {reference_path}")
        return False

    config_block = load_configs(component_dir, globs)
    if not config_block:
        print(f"  [skip] {name}: no config files found")
        return False

    current_doc = reference_path.read_text()

    user_message = textwrap.dedent(f"""\
        Component: {name}

        ## Current config files

        {config_block}

        ## Current reference.md

        {current_doc}

        Review the config files and update the reference.md to reflect any changes.
        Return only the updated markdown.
    """)

    print(f"  [{name}] calling model...")
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        temperature=0.2,
        max_tokens=4096,
    )

    updated = response.choices[0].message.content.strip()

    # Strip markdown code fence if the model wrapped the output
    if updated.startswith("```markdown"):
        updated = updated[len("```markdown"):].lstrip("\n")
        if updated.endswith("```"):
            updated = updated[:-3].rstrip("\n")
    elif updated.startswith("```"):
        updated = updated[3:].lstrip("\n")
        if updated.endswith("```"):
            updated = updated[:-3].rstrip("\n")

    if updated == current_doc.strip():
        print(f"  [{name}] no changes")
        return False

    reference_path.write_text(updated + "\n")
    print(f"  [{name}] updated")
    return True

def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(
        base_url="https://models.inference.ai.azure.com",
        api_key=token,
    )

    changed = []
    for slug, name, globs in COMPONENTS:
        try:
            if update_component(client, slug, name, globs):
                changed.append(name)
        except Exception as exc:
            print(f"  [{name}] ERROR: {exc}", file=sys.stderr)

    if changed:
        print(f"\nUpdated: {', '.join(changed)}")
    else:
        print("\nNo changes.")

if __name__ == "__main__":
    main()
