#!/usr/bin/env bash
# CI grep gates that the linter cannot express.
# Run from ftf-backend/.

set -euo pipefail

fail=0

# 1. db.ServicePool may only be referenced by the narrow set of packages that
# legitimately need privileged DB access. Everything else MUST go through
# *db.UserPool so RLS is the gate.
#
# The two service-pool consumers outside cmd/ are:
#
#   - internal/notifications/   (worker draining the queue; obvious need)
#   - internal/subscribers/     (token-gated state transitions for
#                                confirm/unsubscribe + the per-email throttle
#                                read of notifications, which anon cannot do
#                                under the post-0006 grants)
#   - internal/admins/service.go (admin-only resend-confirm uses the
#                                subscribers service via an interface, but
#                                also injects the pool for cohesion)
#
# HandleSubscribe — the only anon-reachable write handler in subscribers —
# no longer touches ServicePool. It writes through UserPool with role=anon
# and the RLS policies in migration 0006.
allowed_servicepool_paths=(
  "cmd/server/main.go"
  "internal/db/"
  "internal/notifications/"
  "internal/subscribers/"
  "internal/admins/service.go"
)
allowed_re="^($(IFS='|'; echo "${allowed_servicepool_paths[*]}"))"

while IFS= read -r match; do
  path="${match%%:*}"
  if ! [[ "$path" =~ $allowed_re ]]; then
    echo "FORBIDDEN db.ServicePool reference: $match" >&2
    fail=1
  fi
done < <(grep -rn "db\.ServicePool" internal cmd || true)

# 1b. The public subscribe handler must NOT touch ServicePool. We grep for the
# specific method body. If HandleSubscribe ever calls ServicePool again this
# fires. The throttle helper recentlyNotified is exempted via its own check.
if grep -nE 'func .* HandleSubscribe' internal/subscribers/service.go >/dev/null; then
  body=$(awk '/^func .* HandleSubscribe/,/^}$/' internal/subscribers/service.go)
  if echo "$body" | grep -q 'ServicePool\.'; then
    echo "FORBIDDEN: HandleSubscribe references ServicePool directly" >&2
    fail=1
  fi
fi

# 2. Raw SQL string concatenation outside internal/db is banned.
while IFS= read -r match; do
  path="${match%%:*}"
  if [[ "$path" == internal/db/* ]]; then
    continue
  fi
  echo "FORBIDDEN dynamic SQL outside internal/db: $match" >&2
  fail=1
done < <(grep -rEn 'fmt\.Sprintf\("(SELECT|INSERT|UPDATE|DELETE)' internal cmd 2>/dev/null || true)

# 3. Email-in-log gate: any slog call that mentions a literal "email" key
# without an adjacent "_hash" or "to_hash" alternative is suspicious.
while IFS= read -r match; do
  path="${match%%:*}"
  if [[ "$path" == */httpx/logging.go ]]; then
    continue
  fi
  if [[ "$match" == *"to_hash"* ]] || [[ "$match" == *"_hash"* ]]; then
    continue
  fi
  echo "SUSPECT email-in-log: $match" >&2
  fail=1
done < <(grep -rn 'slog\.\(Info\|Warn\|Error\|Debug\).*"email"' internal cmd 2>/dev/null || true)

# 4. Bare crypto/sha256.Sum256 of an email is banned outside the keyed-HMAC
# helper. Email hashing MUST go through httpx.HashEmail / HashEmailBytes so
# the per-process HMAC key keeps rainbow tables out of reach.
while IFS= read -r match; do
  path="${match%%:*}"
  if [[ "$path" == */httpx/logging.go ]] || [[ "$path" == *_test.go ]]; then
    continue
  fi
  if [[ "$match" == *"// allow-sha256"* ]]; then
    continue
  fi
  echo "FORBIDDEN bare sha256 outside httpx: $match" >&2
  fail=1
done < <(grep -rn 'sha256\.Sum256' internal cmd 2>/dev/null | grep -i email || true)

if [[ "$fail" -ne 0 ]]; then
  echo "grep_gates.sh: violations found" >&2
  exit 1
fi
echo "grep_gates.sh: clean"
