#!/usr/bin/env bash
# BannKenn Release Script
# Usage: ./scripts/release.sh [version]
# Example: ./scripts/release.sh 0.2.0
# Example: ./scripts/release.sh        # bumps patch version, e.g. 1.0.1 -> 1.0.2

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()  { echo -e "\n${CYAN}==>${NC} $*"; }

increment_patch_version() {
    local version="$1"

    if ! [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        error "Cannot auto-increment non-release version '$version'. Pass an explicit semver version."
    fi

    local major="${BASH_REMATCH[1]}"
    local minor="${BASH_REMATCH[2]}"
    local patch="${BASH_REMATCH[3]}"

    printf '%s.%s.%s\n' "$major" "$minor" "$((patch + 1))"
}

# ── Validate input ────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TOML="$REPO_ROOT/Cargo.toml"
CURRENT_VERSION="$(grep '^version' "$CARGO_TOML" | head -1 | sed 's/.*= *"\(.*\)"/\1/')"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    VERSION="$(increment_patch_version "$CURRENT_VERSION")"
    info "No version supplied; auto-incrementing patch version ${CURRENT_VERSION} → ${VERSION}"
fi

# Strip leading 'v' if supplied
VERSION="${VERSION#v}"
TAG="v${VERSION}"

# Basic semver sanity check
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    error "Version must be semver format (e.g. 1.2.3 or 1.2.3-beta.1)"
fi

CHANGELOG_DIR="$REPO_ROOT/scripts/version"
CHANGELOG_FILE="$CHANGELOG_DIR/changelog.md"

mkdir -p "$CHANGELOG_DIR"

# ── Pre-flight checks ─────────────────────────────────────────────────────────

step "Pre-flight checks"

if ! command -v git &>/dev/null; then
    error "git is not installed"
fi

cd "$REPO_ROOT"

if [[ -n "$(git status --porcelain)" ]]; then
    error "Working directory is not clean. Commit or stash your changes first."
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
    warn "You are on branch '$CURRENT_BRANCH', not main/master."
    read -rp "Continue anyway? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
fi

if git tag --list | grep -qx "$TAG"; then
    error "Tag $TAG already exists."
fi

info "Releasing $TAG from branch '$CURRENT_BRANCH'"

# ── Update version in Cargo.toml ─────────────────────────────────────────────

step "Updating version in Cargo.toml"

if [[ "$CURRENT_VERSION" == "$VERSION" ]]; then
    info "Cargo.toml already at $VERSION, skipping."
else
    sed -i "s/^version = \"${CURRENT_VERSION}\"/version = \"${VERSION}\"/" "$CARGO_TOML"
    info "Updated $CURRENT_VERSION → $VERSION"
    git add "$CARGO_TOML"
fi

# ── Refresh Cargo.lock ───────────────────────────────────────────────────────

step "Refreshing Cargo.lock"

cargo check --workspace >/dev/null

if ! git diff --quiet -- Cargo.lock; then
    info "Cargo.lock updated for version ${VERSION}"
    git add Cargo.lock
else
    info "Cargo.lock already up to date"
fi

# ── Create changelog file ─────────────────────────────────────────────────────

step "Creating changelog: ${TAG}.md"

# Rename existing changelog if present
PREV_TAG_FOR_RENAME=""
if [[ -f "$CHANGELOG_FILE" ]]; then
    PREV_TAG_FOR_RENAME="$(git tag --sort=-version:refname | head -1 2>/dev/null || true)"
    if [[ -n "$PREV_TAG_FOR_RENAME" ]]; then
        mv "$CHANGELOG_FILE" "$CHANGELOG_DIR/${PREV_TAG_FOR_RENAME}.md"
        info "Renamed previous changelog to ${PREV_TAG_FOR_RENAME}.md"
    fi
fi

DATE="$(date +%Y-%m-%d)"

# Gather commits since last tag (or all if no previous tag)
PREV_TAG="$(git tag --sort=-version:refname | head -1 2>/dev/null || true)"
if [[ -n "$PREV_TAG" ]]; then
    COMMIT_LOG="$(git log "${PREV_TAG}..HEAD" --oneline --no-merges 2>/dev/null || true)"
else
    COMMIT_LOG="$(git log HEAD --oneline --no-merges 2>/dev/null || true)"
fi

cat > "$CHANGELOG_FILE" <<EOF
# Changelog — ${TAG}

**Release date:** ${DATE}

## What's Changed

EOF

if [[ -n "$COMMIT_LOG" ]]; then
    while IFS= read -r line; do
        echo "- ${line}" >> "$CHANGELOG_FILE"
    done <<< "$COMMIT_LOG"
else
    echo "- (no commits since last release)" >> "$CHANGELOG_FILE"
fi

cat >> "$CHANGELOG_FILE" <<EOF

## Install

**Linux x64:**
\`\`\`bash
curl -Lo bannkenn-agent https://github.com/OpenTech-Lab/bannkenn/releases/download/${TAG}/bannkenn-agent-linux-x64
chmod +x bannkenn-agent && sudo mv bannkenn-agent /usr/local/bin/
\`\`\`

**Linux ARM64:**
\`\`\`bash
curl -Lo bannkenn-agent https://github.com/OpenTech-Lab/bannkenn/releases/download/${TAG}/bannkenn-agent-linux-arm64
chmod +x bannkenn-agent && sudo mv bannkenn-agent /usr/local/bin/
\`\`\`

**Windows (PowerShell):**
\`\`\`powershell
Invoke-WebRequest -Uri https://github.com/OpenTech-Lab/bannkenn/releases/download/${TAG}/bannkenn-agent-windows-x64.exe -OutFile bannkenn-agent.exe
\`\`\`

## Full Changelog

https://github.com/OpenTech-Lab/bannkenn/compare/${PREV_TAG:-HEAD}...${TAG}
EOF

mv "$CHANGELOG_FILE" "$CHANGELOG_DIR/${TAG}.md"
CHANGELOG_FILE="$CHANGELOG_DIR/${TAG}.md"
info "Created ${TAG}.md"

git add "$CHANGELOG_FILE"
# Stage renamed previous changelog if present
if [[ -n "$PREV_TAG_FOR_RENAME" ]]; then
    git add "$CHANGELOG_DIR/${PREV_TAG_FOR_RENAME}.md" 2>/dev/null || true
fi
git commit -m "chore: release ${TAG}"
info "Committed version bump and changelog"

# ── Tag and push ──────────────────────────────────────────────────────────────

step "Tagging and pushing"

git tag -a "$TAG" -m "Release ${TAG}"
info "Created tag $TAG"

git push origin "$CURRENT_BRANCH"
git push origin "$TAG"
info "Pushed branch and tag to origin"

echo ""
info "Release $TAG triggered."
info "Monitor CI at: https://github.com/OpenTech-Lab/bannkenn/actions"
info "Release page:  https://github.com/OpenTech-Lab/bannkenn/releases/tag/${TAG}"
