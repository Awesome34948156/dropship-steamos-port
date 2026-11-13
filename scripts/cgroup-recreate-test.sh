#!/usr/bin/env bash
#
# Does an nft cgroupv2 rule survive its cgroup being destroyed and recreated?
#
# Why this matters: in Desktop Mode the game sits in app-steam@autostart.service,
# whose path never changes — that is what makes the app's re-apply prompt moot.
# But if a cgroupv2 rule binds to the cgroup *object* resolved when the rule was
# added, rather than to the path it was given, then a Steam restart (which
# destroys and recreates that cgroup at the same path) would leave every block
# matching nothing, silently, while the app still reports them applied. The
# app's staleness check compares paths, so it could not notice.
#
# Throwaway cgroup, throwaway table, removed on exit. Nothing real is touched.

set -uo pipefail

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=scripts/lib/deck-fixture.sh
. "$REPO/scripts/lib/deck-fixture.sh"

TABLE=dropship_recreate_probe
CG=zz_dropship_probe_cgroup
TEST_IP=1.1.1.1

cleanup() {
  as_root nft delete table inet "$TABLE" 2>/dev/null
  as_root rmdir "/sys/fs/cgroup/$CG" 2>/dev/null
}
trap cleanup EXIT

# The in-cgroup probe lives in scripts/lib/deck-fixture.sh, shared with
# spike-cgroup.sh: the shell has to move itself into the cgroup before exec, or
# the fork races the cgroup write.
inode_of() { as_root stat -c '%i' "/sys/fs/cgroup/$CG" 2>/dev/null; }

echo "1. create /sys/fs/cgroup/$CG"
as_root mkdir "/sys/fs/cgroup/$CG" || exit 1
echo "   inode $(inode_of)"

echo
echo "2. install a rule dropping $TEST_IP, scoped to it"
as_root nft add table inet "$TABLE" || exit 1
as_root nft add chain inet "$TABLE" output \
  '{ type filter hook output priority filter; policy accept; }' || exit 1
if err=$(as_root nft add rule inet "$TABLE" output \
           socket cgroupv2 level 1 "\"$CG\"" ip daddr "$TEST_IP" drop \
           comment "\"recreate-probe\"" 2>&1); then
  echo "   installed"
else
  echo "   nft rejected it: $err"
  exit 1
fi

echo
echo "3. probe from inside the cgroup — the rule must bite (expect 000)"
BEFORE=$(probe_in_cgroup "$CG" "$TEST_IP")
echo "   HTTP ${BEFORE:-<could not join>}"

echo
echo "4. destroy the cgroup and recreate it at the same path"
if ! as_root rmdir "/sys/fs/cgroup/$CG"; then
  echo "   rmdir failed (still busy?) — cannot test"
  exit 1
fi
as_root mkdir "/sys/fs/cgroup/$CG" || exit 1
echo "   inode $(inode_of)  (different inode means a genuinely new cgroup)"

echo
echo "5. probe again from the recreated cgroup"
AFTER=$(probe_in_cgroup "$CG" "$TEST_IP")
echo "   HTTP ${AFTER:-<could not join>}"

echo
if [ "$BEFORE" = "000" ] && [ "$AFTER" = "000" ]; then
  echo "VERDICT: still blocked after recreation."
  echo "  The rule follows the path, so a Steam restart does not void it."
  echo "  Desktop Mode's apply-once story holds."
elif [ "$BEFORE" = "000" ]; then
  echo "VERDICT: the rule STOPPED matching once the cgroup was recreated."
  echo "  It binds to the cgroup object from rule-creation time, not the path."
  echo "  Consequence: restarting Steam in Desktop Mode silently voids every"
  echo "  block, and the app cannot detect it by comparing paths. It would need"
  echo "  to notice the cgroup was recreated (its inode changes) and re-apply."
else
  echo "VERDICT: inconclusive (before=${BEFORE:-none} after=${AFTER:-none})."
  echo "  The drop never took effect, so recreation was not actually tested."
fi
