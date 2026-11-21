#!/usr/bin/env bash
# Install the agent skills used in this repository (project scope).
# .agents/skills is shared by Warp, OpenCode, Copilot, Codex, Cursor, ...

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# "<repository> <path to the skill in the repository>"
# Exact paths skip the repository tree traversal.
SKILLS=(
  # 🎨 UI / dashboard (web/)
  "anthropics/skills skills/frontend-design"
  "vercel-labs/agent-skills skills/web-design-guidelines"
  # 🧡 Svelte 5
  "sveltejs/ai-tools packages/opencode/skills/svelte-code-writer"
  "sveltejs/ai-tools packages/opencode/skills/svelte-core-bestpractices"
  # 🧪 Testing
  "microsoft/playwright-cli skills/playwright-cli"
  "github/awesome-copilot skills/test-gap-audit"
  # 🔒 Security
  "github/awesome-copilot skills/security-review"
)

if ! command -v gh > /dev/null 2>&1; then
  echo "❌ GitHub CLI (gh) is not installed: https://cli.github.com/" >&2
  exit 1
fi

# Keep downloaded skills local; do not change the shared .gitignore.
EXCLUDE_FILE="$(git rev-parse --git-path info/exclude)"
mkdir -p "$(dirname "${EXCLUDE_FILE}")"
touch "${EXCLUDE_FILE}"
if ! grep -Fqx "/.agents/skills/" "${EXCLUDE_FILE}"; then
  printf '\n/.agents/skills/\n' >> "${EXCLUDE_FILE}"
  echo "🙈 Added /.agents/skills/ to ${EXCLUDE_FILE}"
fi

INSTALLED=0
SKIPPED=0
FAILED=()

echo "🧰 Installing ${#SKILLS[@]} agent skills into ${ROOT_DIR}/.agents/skills"
for ENTRY in "${SKILLS[@]}"; do
  read -r REPOSITORY SKILL_PATH <<< "${ENTRY}"
  SKILL="${SKILL_PATH##*/}"

  if [[ -f ".agents/skills/${SKILL}/SKILL.md" ]]; then
    echo "✅ ${SKILL} (already installed)"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  echo "📦 ${SKILL} (${REPOSITORY})"
  if gh skill install "${REPOSITORY}" "${SKILL_PATH}" --agent warp --scope project; then
    INSTALLED=$((INSTALLED + 1))
  else
    echo "⚠️  Failed to install ${SKILL}" >&2
    FAILED+=("${SKILL}")
  fi
done

echo
echo "🆕 Installed: ${INSTALLED}  ⏭️  Skipped: ${SKIPPED}  💥 Failed: ${#FAILED[@]}"
echo "💡 Update them later with: gh skill update --all"

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "❌ Failed skills: ${FAILED[*]}" >&2
  exit 1
fi

echo "🎉 Done"
