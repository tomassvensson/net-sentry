#!/usr/bin/env bash
# Push the current branch to GitLab first, wait for its pipeline (.gitlab-ci.yml, a
# mirror of .github/workflows/ci.yml), and only push to GitHub once it is green.
# Iterate on GitLab; GitHub only ever sees commits that already passed.
#
# Usage: scripts/push-via-gitlab.sh [options]
#   --gitlab-only     Push to GitLab and wait for the pipeline; never push to GitHub
#   --no-windows      Skip the Windows test jobs on GitLab (they take ~8 min each)
#   --no-watch        Don't wait for the GitHub Actions run after pushing to GitHub
#   --force           Force-push (--force-with-lease) to both remotes
#   -h, --help        Show this help
#
# Environment:
#   GITLAB_PROJECT    GitLab project path (default: <glab user>/<GitHub repo name>)
#   GITLAB_REMOTE     Git remote name for GitLab (default: gitlab)
#   GITHUB_REMOTE     Git remote name for GitHub (default: origin)
#   PIPELINE_TIMEOUT  Seconds to wait for the GitLab pipeline (default: 3600)
#   LOG_LINES         Lines of each failed job's log to print (default: 150)
#
# Requires: git, glab, gh, jq (glab and gh logged in with write access).
# The GitLab project is created on first run if it does not exist.

set -euo pipefail

GITLAB_REMOTE="${GITLAB_REMOTE:-gitlab}"
GITHUB_REMOTE="${GITHUB_REMOTE:-origin}"
PIPELINE_TIMEOUT="${PIPELINE_TIMEOUT:-3600}"
LOG_LINES="${LOG_LINES:-150}"

gitlab_only=false
no_windows=false
watch_github=true
force=false

usage() { sed -n '2,/^$/{s/^# \{0,1\}//;p}' "$0"; }
log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gitlab-only) gitlab_only=true ;;
    --no-windows) no_windows=true ;;
    --no-watch) watch_github=false ;;
    --force) force=true ;;
    -h | --help) usage; exit 0 ;;
    *) die "Unknown option: $1 (see --help)" ;;
  esac
  shift
done

for cmd in git glab gh jq; do
  command -v "$cmd" >/dev/null || die "'$cmd' is not installed"
done

cd "$(git rev-parse --show-toplevel)"

branch="$(git symbolic-ref --short HEAD 2>/dev/null)" || die "Detached HEAD; check out a branch first"
sha="$(git rev-parse HEAD)"
short_sha="${sha:0:7}"

if [[ -n "$(git status --porcelain)" ]]; then
  warn "Uncommitted changes are NOT part of the push (commit them first if they matter)"
fi

# --- Resolve GitHub repo and GitLab project -----------------------------------

github_url="$(git remote get-url "$GITHUB_REMOTE")" || die "No '$GITHUB_REMOTE' remote"
repo_name="$(basename "$github_url" .git)"
github_repo="$(gh repo view "${github_url%.git}" --json nameWithOwner -q .nameWithOwner)" ||
  die "gh cannot access $github_url (run: gh auth status)"

if [[ -z "${GITLAB_PROJECT:-}" ]]; then
  gitlab_user="$(glab api user | jq -r .username)" || die "glab is not logged in (run: glab auth status)"
  GITLAB_PROJECT="$gitlab_user/$repo_name"
fi
project_id="$(jq -rn --arg p "$GITLAB_PROJECT" '$p | @uri')"
gitlab_web="https://gitlab.com/$GITLAB_PROJECT"

# A project scheduled for deletion is renamed to <path>-deletion_scheduled-<id> but
# still answers on the old path, so match on the real path, not on a 200 response.
existing_path="$(glab api "projects/$project_id" 2>/dev/null | jq -r '.path_with_namespace // empty')"
if [[ "$existing_path" != "$GITLAB_PROJECT" ]]; then
  visibility="$(gh repo view "$github_repo" --json visibility -q '.visibility | ascii_downcase' 2>/dev/null || echo private)"
  log "Creating GitLab project $GITLAB_PROJECT ($visibility)"
  glab api -X POST projects \
    -f "name=$repo_name" \
    -f "path=$(basename "$GITLAB_PROJECT")" \
    -f "visibility=$visibility" \
    -f "initialize_with_readme=false" \
    -f "description=CI proving ground for $github_url. Pushed via scripts/push-via-gitlab.sh." >/dev/null ||
    die "Could not create $GITLAB_PROJECT (a project scheduled for deletion may still hold the path)"
fi
# --no-windows passes a pipeline variable via git push option. New projects let no one
# do that and GitLab silently drops the pipeline, so allow it for maintainers.
glab api -X PUT "projects/$project_id" -f ci_pipeline_variables_minimum_override_role=maintainer >/dev/null ||
  warn "Could not allow pipeline variables on $GITLAB_PROJECT; --no-windows may not work"

gitlab_url="$gitlab_web.git"
if current_url="$(git remote get-url "$GITLAB_REMOTE" 2>/dev/null)"; then
  [[ "$current_url" == "$gitlab_url" ]] || warn "Remote '$GITLAB_REMOTE' points at $current_url, not $gitlab_url"
else
  log "Adding git remote '$GITLAB_REMOTE' -> $gitlab_url"
  git remote add "$GITLAB_REMOTE" "$gitlab_url"
fi

push_flags=()
$force && push_flags+=(--force-with-lease)

# --- Push to GitLab and wait for the pipeline ---------------------------------

gitlab_push_opts=()
$no_windows && gitlab_push_opts+=(-o 'ci.variable=SKIP_WINDOWS=1')

log "Pushing $branch ($short_sha) to GitLab: $gitlab_web"
git push "${push_flags[@]}" "${gitlab_push_opts[@]}" "$GITLAB_REMOTE" "HEAD:refs/heads/$branch"

log "Waiting for the GitLab pipeline to appear"
pipeline_id=""
for _ in $(seq 1 60); do
  pipeline_id="$(glab api "projects/$project_id/pipelines?sha=$sha&ref=$branch&per_page=1" | jq -r '.[0].id // empty')"
  [[ -n "$pipeline_id" ]] && break
  sleep 5
done
if [[ -z "$pipeline_id" ]]; then
  die "No pipeline appeared for $short_sha. Check $gitlab_web/-/pipelines (CI/CD enabled? account verified for hosted runners?)"
fi

pipeline_url="$gitlab_web/-/pipelines/$pipeline_id"
log "Pipeline: $pipeline_url"

start=$SECONDS
last_status=""
while :; do
  status="$(glab api "projects/$project_id/pipelines/$pipeline_id" | jq -r .status)"
  if [[ "$status" != "$last_status" ]]; then
    log "Pipeline status: $status ($(( (SECONDS - start) / 60 ))m elapsed)"
    last_status="$status"
  fi
  case "$status" in
    success | failed | canceled | skipped) break ;;
  esac
  (( SECONDS - start < PIPELINE_TIMEOUT )) || die "Timed out after ${PIPELINE_TIMEOUT}s waiting for $pipeline_url"
  sleep 15
done

if [[ "$status" != "success" ]]; then
  yaml_errors="$(glab api "projects/$project_id/pipelines/$pipeline_id" | jq -r '.yaml_errors // empty')"
  [[ -n "$yaml_errors" ]] && printf '\n.gitlab-ci.yml errors:\n%s\n' "$yaml_errors" >&2

  glab api "projects/$project_id/pipelines/$pipeline_id/jobs?scope[]=failed&per_page=100" |
    jq -r '.[] | select(.allow_failure | not) | "\(.id)\t\(.name)"' |
    while IFS=$'\t' read -r job_id job_name; do
      printf '\n\033[1;31m----- FAILED: %s (%s/-/jobs/%s) -----\033[0m\n' "$job_name" "$gitlab_web" "$job_id" >&2
      glab api "projects/$project_id/jobs/$job_id/trace" | tail -n "$LOG_LINES" >&2
    done
  die "GitLab pipeline $status: $pipeline_url. NOT pushing to GitHub. Fix, commit, re-run."
fi

log "GitLab pipeline passed: $pipeline_url"

if $gitlab_only; then
  log "--gitlab-only: not pushing to GitHub"
  exit 0
fi

# --- Push to GitHub -----------------------------------------------------------

# Forks have Actions disabled until someone enables them; do it so the push gets a run.
if [[ "$(gh api "repos/$github_repo/actions/permissions" -q .enabled 2>/dev/null)" == "false" ]]; then
  log "GitHub Actions is disabled on $github_repo; enabling it"
  gh api -X PUT "repos/$github_repo/actions/permissions" -F enabled=true -f allowed_actions=all >/dev/null ||
    warn "Could not enable Actions; enable them at https://github.com/$github_repo/actions"
fi

log "Pushing $branch ($short_sha) to GitHub: https://github.com/$github_repo"
git push "${push_flags[@]}" "$GITHUB_REMOTE" "HEAD:refs/heads/$branch"

$watch_github || exit 0

log "Waiting for the GitHub Actions run to appear"
run_id=""
for _ in $(seq 1 12); do
  run_id="$(gh run list -R "$github_repo" --commit "$sha" --limit 1 --json databaseId -q '.[0].databaseId // empty' 2>/dev/null || true)"
  [[ -n "$run_id" ]] && break
  sleep 5
done

if [[ -z "$run_id" ]]; then
  warn "No GitHub Actions run for $short_sha (ci.yml only runs on pushes to main and on PRs)"
  exit 0
fi

run_url="https://github.com/$github_repo/actions/runs/$run_id"
log "GitHub run: $run_url"
if ! gh run watch "$run_id" -R "$github_repo" --exit-status --interval 15; then
  die "GitHub Actions failed although GitLab passed. Differences are GitHub-only jobs (SonarCloud, CodeQL) or runner images. Logs: gh run view $run_id -R $github_repo --log-failed"
fi
log "GitHub Actions passed: $run_url"
