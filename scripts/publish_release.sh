#!/usr/bin/env bash
# Publish a GitHub release from the assets built by the Release workflow, under your own account.
#
#   git tag -a v1.2.3 -m "RLS Sentinel 1.2.3" && git push origin v1.2.3   # starts the Release workflow
#   scripts/publish_release.sh v1.2.3                                    # after the workflow has succeeded
#
# Requires the GitHub CLI (gh), logged in as the repository owner.
set -euo pipefail
tag=${1:?usage: scripts/publish_release.sh vX.Y.Z}
cd "$(dirname "$0")/.."

run_id=$(gh run list --workflow Release --branch "$tag" --status success --limit 1 --json databaseId --jq '.[0].databaseId')
[ -n "$run_id" ] || { echo "no successful Release workflow run for $tag yet"; exit 1; }

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
gh run download "$run_id" --name "release-$tag" --dir "$out"
(cd "$out" && sha256sum -c SHA256SUMS)
for f in "$out"/*.whl "$out"/*.tar.gz; do
  gh attestation verify "$f" --repo "$(gh repo view --json nameWithOwner --jq .nameWithOwner)" >/dev/null
done
gh release create "$tag" "$out"/* --verify-tag --title "$tag" --notes-file CHANGELOG.md
echo "published $tag"
