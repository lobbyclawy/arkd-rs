#!/usr/bin/env bash
# Build the anonymized export branch for double-blind submission.
# Anonymous GitHub blinds paths and strips git metadata but does not touch
# file contents, so author identity has to be scrubbed here.
#
#   scripts/anonymize.sh [source-ref]     # default: HEAD
#   git push -f origin anon-export        # then anonymize that branch
set -euo pipefail

# wrapped so bash parses the whole script before it deletes itself below
main() {
  local src="${1:-HEAD}" branch="anon-export" files
  cd "$(git rev-parse --show-toplevel)"
  git diff --quiet && git diff --cached --quiet || {
    echo "working tree is dirty; commit or stash first" >&2
    exit 1
  }

  git switch -C "$branch" "$src"

  # both name the authors and neither belongs in the public mirror
  git rm -q --ignore-unmatch FC27-RESULTS.md scripts/anonymize.sh

  files=$(git grep -lIi -e lobby -e carotti -e gmail || true)
  if [ -n "$files" ]; then
    printf '%s\n' "$files" | xargs perl -pi \
      -e 's/^authors = \[.*\]/authors = ["Anonymous"]/;' \
      -e 's/Lobby & Andrea Carotti/the Authors/g;' \
      -e 's/lobbyclawy/anon/g;' \
      -e 's/[A-Za-z0-9._%+-]+\@gmail\.com/anon\@example.org/g;' \
      -e 's/Andrea Carotti/Anonymous/g;' \
      -e 's/\bLobby\b/Anonymous/g;'
  fi

  git commit -qam "chore: anonymized export"

  # the scrub is a substitution list; this is what actually guarantees it
  if git grep -Iin -e lobby -e carotti -e gmail; then
    echo "FAIL: identity terms survived the scrub (listed above)" >&2
    exit 1
  fi
  echo "OK: '$branch' is clean. Push it, then point 4open.science at that branch."
}

main "$@"
