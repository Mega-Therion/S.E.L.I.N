#!/usr/bin/env python3
"""
Sync chyren-selin governance specifications, runtime manifests, and documentation
to Hugging Face dataset repository: ChyRho/chyren-selin.
"""

import os
import sys
from pathlib import Path
from huggingface_hub import HfApi

REPO_ID = "ChyRho/chyren-selin"
REPO_ROOT = Path(__file__).resolve().parent.parent

def get_token():
    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")
    if not token:
        raise RuntimeError(
            "HF_TOKEN not found in environment. "
            "Export HF_TOKEN=<your-token> before running this script."
        )
    return token

def generate_hf_readme():
    return """---
license: apache-2.0
pretty_name: "Chyren Selin: Sovereign AI Governance Node & ARCHON Runtime"
tags:
  - ai-governance
  - formal-verification
  - archon
  - rust
---

# Chyren Selin: Sovereign AI Governance Node & ARCHON Runtime

Local-first, encrypted, fail-closed mathematical verification and autonomous governance node.

---

### 🔗 Canonical Links & Provenance

- **GitHub Source of Truth**: [https://github.com/Mega-Therion/chyren-selin](https://github.com/Mega-Therion/chyren-selin)
- **Interactive Research Atlas**: [https://res-nova-atlas.vercel.app](https://res-nova-atlas.vercel.app)
- **Author**: R.W. Yett ([ORCID: 0009-0001-1303-7190](https://orcid.org/0009-0001-1303-7190))
- **LinkedIn**: [R.W. Yett](https://www.linkedin.com/in/r-w-yett/)
- **X (Twitter)**: [@_ChyRho_](https://x.com/_chyrho_)

---

### 📂 Architecture & Assets

- `archon_kernel/`: Core Rust verification kernel enforcing invariant satisfaction and bounds.
- `cli/`: Sovereign governance and operator runtime interface.
- `docs/`: Governance architecture, threat modeling, and protocol specifications.
"""

def main():
    token = get_token()
    api = HfApi(token=token)
    print(f"Ensuring repository {REPO_ID} exists...")
    api.create_repo(repo_id=REPO_ID, repo_type="dataset", exist_ok=True)

    print("Uploading Hugging Face dataset card README.md...")
    api.upload_file(
        path_or_fileobj=generate_hf_readme().encode("utf-8"),
        path_in_repo="README.md",
        repo_id=REPO_ID,
        repo_type="dataset",
        commit_message="docs: update dataset card with cross-platform links and Selin metadata"
    )

    dirs_to_upload = ["archon_kernel", "cli", "docs", "templates"]
    for d in dirs_to_upload:
        folder_path = REPO_ROOT / d
        if folder_path.exists():
            print(f"Uploading directory {d}...")
            api.upload_folder(
                folder_path=str(folder_path),
                path_in_repo=d,
                repo_id=REPO_ID,
                repo_type="dataset",
                commit_message=f"sync: upload {d} to Hugging Face dataset"
            )

    root_files = ["Cargo.toml", "CHANGELOG.md", "PRODUCT_TRIANGLE.md", "LICENSE"]
    for rf in root_files:
        fp = REPO_ROOT / rf
        if fp.exists():
            print(f"Uploading {rf}...")
            api.upload_file(
                path_or_fileobj=str(fp),
                path_in_repo=rf,
                repo_id=REPO_ID,
                repo_type="dataset",
                commit_message=f"sync: upload {rf}"
            )

    print(f"Successfully synced chyren-selin to https://huggingface.co/datasets/{REPO_ID}")

if __name__ == "__main__":
    main()
