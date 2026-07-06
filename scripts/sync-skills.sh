#!/usr/bin/env bash
# Sync agent-updated skills from ~/.hermes/skills/ back to the plugin repo,
# then commit + push any changes.
set -euo pipefail

REPO_ROOT="${HOME}/.hermes/plugins/secmon"
SKILLS_SRC="${HOME}/.hermes/skills/devops"
SKILLS_DST="${REPO_ROOT}/skills"

# Skills to sync — directory name under both ~/.hermes/skills/devops/ and plugin skills/
SKILL_NAMES=(
  hermes-secmon
  secmon-maintenance
  secmon-audit-output-tuning
)

changes=0

for name in "${SKILL_NAMES[@]}"; do
  src="${SKILLS_SRC}/${name}"
  dst="${SKILLS_DST}/${name}"

  if [[ ! -d "${src}" ]]; then
    echo "  [SKIP] ${name}: not found in ${SKILLS_SRC}/"
    continue
  fi

  # Copy entire skill directory (SKILL.md + references/ + scripts/)
  mkdir -p "${dst}"
  rsync -a --delete "${src}/" "${dst}/"

  # Check if anything actually changed
  if ! git -C "${REPO_ROOT}" diff --quiet -- "skills/${name}/"; then
    echo "  [UPDATED] ${name}"
    changes=1
  else
    echo "  [OK] ${name}"
  fi
done

if [[ "${changes}" -eq 0 ]]; then
  echo "No changes to commit."
  exit 0
fi

echo ""
cd "${REPO_ROOT}"
git add skills/

# Only commit if there are actually staged changes
if git diff --cached --quiet; then
  echo "No staged changes after rsync — nothing to commit."
  exit 0
fi

git commit -m "chore(skills): sync agent-updated skills from ~/.hermes/skills/" --author="Hermes Agent <hermes@nousresearch.com>"
git push origin main
echo "Committed and pushed skill updates."