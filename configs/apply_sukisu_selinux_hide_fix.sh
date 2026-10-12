#!/usr/bin/env bash
set -euo pipefail

: "${KSU_FOLDER:?KSU_FOLDER is required}"
: "${COMMON_KERNEL_FOLDER:?COMMON_KERNEL_FOLDER is required}"
: "${ANDROID_VER_LOCAL:?ANDROID_VER_LOCAL is required}"
: "${KERNEL_VER_LOCAL:?KERNEL_VER_LOCAL is required}"

if [[ "$ANDROID_VER_LOCAL" != "android14" || "$KERNEL_VER_LOCAL" != "6.1" ]]; then
  exit 0
fi

ensure_backup_sepolicy_api() {
  local root="$1"
  local header="$root/selinux/sepolicy.h"
  local rules="$root/selinux/rules.c"

  [[ -f "$header" ]] || return 0

  if ! grep -qE '^[[:space:]]*extern[[:space:]]+struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$header"; then
    python3 - "$header" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
line = 'extern struct selinux_policy *backup_sepolicy;'
if line not in s:
    marker = 'struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol);'
    if marker in s:
        s = s.replace(marker, line + '\n\n' + marker, 1)
    else:
        s = s.replace('#endif', line + '\n\n#endif', 1)
    p.write_text(s)
PY
  fi

  if [[ -f "$rules" ]] && ! grep -qE '^[[:space:]]*struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$rules"; then
    python3 - "$rules" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
line = 'struct selinux_policy *backup_sepolicy;'
if line not in s:
    marker = '#include "sepolicy.h"'
    if marker in s:
        s = s.replace(marker, marker + '\n\n' + line, 1)
    else:
        s = line + '\n' + s
    p.write_text(s)
PY
  fi

  grep -qE '^[[:space:]]*extern[[:space:]]+struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$header"
  if [[ -f "$rules" ]]; then
    grep -qE '^[[:space:]]*struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$rules"
  fi
}

patch_lsm_hook() {
  local target="$1"
  [[ -f "$target" ]] || return 0

  python3 - "$target" <<'PY'
from pathlib import Path
import re, sys
p = Path(sys.argv[1])
s = p.read_text()

helper = '''static bool ksu_lsm_hook_target_matches(void *current_origin, void *target)
{
    unsigned long start, current_addr;
    unsigned long size = 0, current_size = 0;
    char target_sym[KSYM_SYMBOL_LEN];
    char current_sym[KSYM_SYMBOL_LEN];
    char *p;

    if (!current_origin || !target)
        return false;

    if (current_origin == target)
        return true;

    start = (unsigned long)target;
    current_addr = (unsigned long)current_origin;

    /* First handle normal LTO/ICF aliases which remain inside the symbol. */
    if (kallsyms_lookup_size_offset(start, &size, NULL) && size &&
        current_addr >= start && current_addr < start + size)
        return true;

    /*
     * Some Android 14/6.1 KCFI+LTO builds register a separate local alias
     * (foo.llvm.<hash>) in the LSM hlist.  That alias can sit outside the
     * bare kallsyms symbol range, so compare normalized kallsyms names too.
     */
    if (!kallsyms_lookup(start, &size, NULL, NULL, target_sym))
        return false;
    if (!kallsyms_lookup(current_addr, &current_size, NULL, NULL, current_sym))
        return false;


    p = strstr(target_sym, ".llvm.");
    if (p) *p = '\\0';
    p = strstr(target_sym, ".constprop.");
    if (p) *p = '\\0';
    p = strstr(target_sym, ".isra.");
    if (p) *p = '\\0';
    p = strstr(target_sym, ".part.");
    if (p) *p = '\\0';
    p = strstr(target_sym, ".cfi_jt");
    if (p) *p = '\\0';

    p = strstr(current_sym, ".llvm.");
    if (p) *p = '\\0';
    p = strstr(current_sym, ".constprop.");
    if (p) *p = '\\0';
    p = strstr(current_sym, ".isra.");
    if (p) *p = '\\0';
    p = strstr(current_sym, ".part.");
    if (p) *p = '\\0';
    p = strstr(current_sym, ".cfi_jt");
    if (p) *p = '\\0';

    if (!strcmp(target_sym, current_sym)) {
        pr_info("lsm_hook: alias match %s -> %s\\n", target_sym, current_sym);
        return true;
    }

    return false;
}
'''

if 'ksu_lsm_hook_target_matches' not in s:
    m = re.search(r'\nint\s+ksu_lsm_hook\s*\(\s*struct\s+ksu_lsm_hook\s*\*hook\s*\)\s*\{', s)
    if not m:
        raise SystemExit(f'Cannot locate ksu_lsm_hook() in {p}; refusing unrelated changes')
    s = s[:m.start()] + '\n' + helper + s[m.start():]

pattern = r'if\s*\(\s*current_origin\s*==\s*target\s*\)\s*\{'
s2, n = re.subn(pattern, 'if (ksu_lsm_hook_target_matches(current_origin, target)) {', s)
if n:
    s = s2
elif 'ksu_lsm_hook_target_matches(current_origin, target)' not in s:
    raise SystemExit(f'Cannot locate SukiSU target comparison in {p}; refusing unrelated changes')

p.write_text(s)
PY
}

ensure_backup_sepolicy_api "$KSU_FOLDER/kernel"
ensure_backup_sepolicy_api "$COMMON_KERNEL_FOLDER/drivers/kernelsu"

patch_lsm_hook "$KSU_FOLDER/kernel/hook/lsm_hook.c"
patch_lsm_hook "$COMMON_KERNEL_FOLDER/drivers/kernelsu/hook/lsm_hook.c"

COMMON_HIDE="$COMMON_KERNEL_FOLDER/drivers/kernelsu/feature/selinux_hide.c"
COMMON_LSM="$COMMON_KERNEL_FOLDER/drivers/kernelsu/hook/lsm_hook.c"
COMMON_SEPOLICY_H="$COMMON_KERNEL_FOLDER/drivers/kernelsu/selinux/sepolicy.h"
COMMON_RULES="$COMMON_KERNEL_FOLDER/drivers/kernelsu/selinux/rules.c"

for f in "$COMMON_HIDE" "$COMMON_LSM" "$COMMON_SEPOLICY_H" "$COMMON_RULES"; do
  [[ -f "$f" ]] || { echo "::error::Missing SukiSU SELinux-hide source: $f"; exit 1; }
done

grep -q 'backup_sepolicy' "$COMMON_HIDE"
grep -qE '^[[:space:]]*extern[[:space:]]+struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$COMMON_SEPOLICY_H"
grep -qE '^[[:space:]]*struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$COMMON_RULES"
grep -q 'ksu_lsm_hook_target_matches(current_origin, target)' "$COMMON_LSM"

echo "SukiSU SELinux-hide API is internally consistent"
echo "  backup_sepolicy: declaration + definition verified"
echo "  common-tree LSM matcher: verified"
