#!/usr/bin/env python3
"""
Two modes depending on EVENT_NAME:

  pull_request  — analyse changed config files against the current reference.md,
                  post a comment with findings, update the reference.md in-place,
                  and emit a review verdict (approve / request-changes).

  schedule /    — full refresh: rewrite all reference.md files to reflect the
  workflow_dispatch   current config. Caller opens a PR with the changes.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from openai import OpenAI

REPO_ROOT = Path(__file__).parents[2]
CORE = REPO_ROOT / "kubernetes" / "core"

# (slug, display name, config files to feed to the model)
COMPONENTS = [
    ("cilium",        "Cilium",        ["values.yml", "pools.yml", "policy.yml", "helm-release.yml"]),
    ("coredns",       "CoreDNS",       ["values.yml", "helm-release.yml"]),
    ("flux-instance", "Flux Instance", ["values.yml", "helm-release.yml", "components/kustomization.yml"]),
    ("gateway-api",   "Gateway API",   ["flux-kustomization.yml", "certificate.yml", "private-class.yml", "public-class.yml", "redirect-route.yml"]),
    ("prometheus",    "Prometheus",    ["helm-release.yml", "alert-manager-config.yml"]),
    ("rook-ceph",     "Rook-Ceph",     ["helm-release.yml", "cluster/helm-release.yml"]),
    ("spegel",        "Spegel",        ["values.yml", "helm-release.yml"]),
]

# Map config file paths → component slug for PR mode lookup
PATH_TO_SLUG: dict[str, str] = {}
for slug, _, globs in COMPONENTS:
    for g in globs:
        PATH_TO_SLUG[f"kubernetes/core/{slug}/{g}"] = slug

SYSTEM_UPDATE = textwrap.dedent("""\
    You are a technical documentation assistant maintaining reference docs for a personal Kubernetes homelab cluster.
    The docs are written in a terse, direct style: tables for field-level detail, minimal prose, no filler phrases.
    Descriptions are short fragments, not full sentences. Bold is used sparingly.
    The audience is the author themselves — technically fluent, no hand-holding needed.

    When updating a reference doc:
    - Only change sections where the config has actually changed (new fields, removed fields, changed values, new behaviour).
    - Preserve all existing content that is still accurate — do not rewrite for style or completeness.
    - Do not add sections that weren't there before unless a genuinely new config area warrants it.
    - Do not add commentary about what you changed — just return the updated doc.
    - Do not make style changes: do not add or remove bold/italic formatting, reword descriptions, or reorder content.
    - Return only the raw markdown content of the updated reference.md, nothing else.
    - If nothing meaningful has changed, return the existing doc unchanged.
""")

SYSTEM_REVIEW = textwrap.dedent("""\
    You are a technical reviewer for a personal Kubernetes homelab cluster managed via Flux and Helm.
    A Renovate PR has updated one or more Helm chart versions or config values.
    Your job is to help the owner decide whether to merge by analysing what changed.

    Respond with a JSON object (no markdown wrapper) with these keys:
      "comment"      — markdown string for a PR comment. Terse, factual, no fluff.
                       Cover: what version bumped, notable changelog items if inferable,
                       any config fields that are affected, anything that could break.
                       Use a table if there are multiple changes. Keep it short.
      "review_event" — one of: "approve", "request-changes", "comment"
                       Use "approve" if the change looks routine and safe.
                       Use "request-changes" if there is a breaking change, a removed field
                       still in use, or something that needs manual action before merging.
                       Use "comment" if uncertain or informational only.
      "review_body"  — one sentence summary used as the formal review body.
      "doc_update"   — updated reference.md content as a string, reflecting the new config.
                       Same style rules as always: terse, table-heavy, no filler.
                       Return null if the reference.md needs no changes.
""")


def load_configs(component_dir: Path, globs: list[str]) -> str:
    parts = []
    for pattern in globs:
        path = component_dir / pattern
        if path.exists():
            parts.append(f"### {path.relative_to(REPO_ROOT)}\n\n```yaml\n{path.read_text()}```")
        else:
            for match in sorted(component_dir.glob(pattern)):
                parts.append(f"### {match.relative_to(REPO_ROOT)}\n\n```yaml\n{match.read_text()}```")
    return "\n\n".join(parts)


def get_changed_slugs() -> list[str]:
    """Return component slugs touched by the current PR via git diff against main."""
    result = subprocess.run(
        ["git", "diff", "--name-only", "origin/main...HEAD"],
        capture_output=True, text=True, cwd=REPO_ROOT
    )
    changed = result.stdout.splitlines()
    slugs = []
    seen = set()
    for path in changed:
        slug = PATH_TO_SLUG.get(path)
        if slug and slug not in seen:
            slugs.append(slug)
            seen.add(slug)
    return slugs


def get_file_diff(path: Path) -> str:
    result = subprocess.run(
        ["git", "diff", "origin/main...HEAD", "--", str(path)],
        capture_output=True, text=True, cwd=REPO_ROOT
    )
    return result.stdout.strip()


def set_output(key: str, value: str) -> None:
    """Write a value to GITHUB_OUTPUT, handling multiline strings."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        print(f"::set-output name={key}::{value}")
        return
    delimiter = "EOF_OUTPUT"
    with open(output_file, "a") as f:
        f.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")


def strip_code_fence(text: str) -> str:
    """Only unwrap if the model wrapped the entire response in a code fence."""
    text = text.strip()
    wrapped = False
    if text.startswith("```markdown"):
        text = text[len("```markdown"):].lstrip("\n")
        wrapped = True
    elif text.startswith("```") and not text.startswith("```\n#"):
        # Only strip if the opening fence isn't itself content (e.g. a bash block)
        text = text[3:].lstrip("\n")
        wrapped = True
    if wrapped and text.endswith("```"):
        text = text[:-3].rstrip("\n")
    return text.strip()


def mode_pr(client: OpenAI) -> None:
    changed_slugs = get_changed_slugs()
    if not changed_slugs:
        print("No tracked components changed in this PR.")
        return

    all_comments: list[str] = []
    overall_verdict = "approve"
    overall_body_parts: list[str] = []

    for slug in changed_slugs:
        component_dir = CORE / slug
        reference_path = component_dir / "reference.md"
        _, name, globs = next(c for c in COMPONENTS if c[0] == slug)

        config_block = load_configs(component_dir, globs)
        current_doc = reference_path.read_text() if reference_path.exists() else "(no reference.md yet)"

        # Build diffs for changed files in this component
        diff_parts = []
        for g in globs:
            p = component_dir / g
            diff = get_file_diff(p)
            if diff:
                diff_parts.append(f"### diff: {p.relative_to(REPO_ROOT)}\n\n```diff\n{diff}\n```")
        diff_block = "\n\n".join(diff_parts) if diff_parts else "(no diff available)"

        user_message = textwrap.dedent(f"""\
            Component: {name}

            ## Git diff (what changed in this PR)

            {diff_block}

            ## Current config files (post-change state)

            {config_block}

            ## Current reference.md

            {current_doc}
        """)

        print(f"  [{name}] calling model...")
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_REVIEW},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            max_tokens=4096,
            response_format={"type": "json_object"},
        )

        raw = response.choices[0].message.content.strip()
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            print(f"  [{name}] failed to parse model response as JSON", file=sys.stderr)
            print(raw, file=sys.stderr)
            continue

        comment = result.get("comment", "")
        review_event = result.get("review_event", "comment")
        review_body = result.get("review_body", "")
        doc_update = result.get("doc_update")

        if comment:
            all_comments.append(f"## {name}\n\n{comment}")

        # Escalate verdict: request-changes > comment > approve
        if review_event == "request-changes":
            overall_verdict = "request-changes"
        elif review_event == "comment" and overall_verdict == "approve":
            overall_verdict = "comment"

        if review_body:
            overall_body_parts.append(f"**{name}**: {review_body}")

        if doc_update:
            cleaned = strip_code_fence(doc_update)
            reference_path.write_text(cleaned + "\n")
            print(f"  [{name}] reference.md updated")
        else:
            print(f"  [{name}] no doc changes needed")

    if all_comments:
        full_comment = "### Reference docs analysis\n\n" + "\n\n---\n\n".join(all_comments)
        set_output("comment", full_comment)
    else:
        set_output("comment", "")

    set_output("review_event", overall_verdict)
    set_output("review_body", " | ".join(overall_body_parts) if overall_body_parts else "Automated reference doc review.")


def mode_update(client: OpenAI) -> None:
    for slug, name, globs in COMPONENTS:
        component_dir = CORE / slug
        reference_path = component_dir / "reference.md"

        if not reference_path.exists():
            print(f"  [skip] {name}: no reference.md")
            continue

        config_block = load_configs(component_dir, globs)
        if not config_block:
            print(f"  [skip] {name}: no config files found")
            continue

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
                {"role": "system", "content": SYSTEM_UPDATE},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            max_tokens=4096,
        )

        updated = strip_code_fence(response.choices[0].message.content)

        if updated == current_doc.strip():
            print(f"  [{name}] no changes")
        else:
            reference_path.write_text(updated + "\n")
            print(f"  [{name}] updated")


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(
        base_url="https://models.inference.ai.azure.com",
        api_key=token,
    )

    event = os.environ.get("EVENT_NAME", "workflow_dispatch")
    if event == "pull_request":
        print("Mode: PR review")
        mode_pr(client)
    else:
        print("Mode: full update")
        mode_update(client)


if __name__ == "__main__":
    main()
