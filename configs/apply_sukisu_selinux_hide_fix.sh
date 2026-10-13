#!/usr/bin/env bash
set -euo pipefail

: "${KSU_FOLDER:?KSU_FOLDER is required}"
: "${COMMON_KERNEL_FOLDER:?COMMON_KERNEL_FOLDER is required}"
: "${ANDROID_VER_LOCAL:?ANDROID_VER_LOCAL is required}"
: "${KERNEL_VER_LOCAL:?KERNEL_VER_LOCAL is required}"
# SELinux-hide is enabled for supported SukiSU layouts across the workflow. The implementation below validates required files/API before modifying the tree.
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

# On some Android 16 / 6.12 trees, the SELinux-hide patch adds a call to
# security_context_to_sid_with_policy() in hooks.c but the matching policy-
# specific helper is not present in services.c. In my_setprocattr, the active
# policy is the current SELinux policy, so use the standard current-policy API
# only when the policy-specific implementation is genuinely absent.
repair_missing_policy_context_helper() {
  local root="$1"
  python3 - "$root" <<'PYPOLICY'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
hooks = root / "security/selinux/hooks.c"
services = root / "security/selinux/ss/services.c"
header = root / "security/selinux/include/security.h"
if not hooks.is_file() or not services.is_file():
    raise SystemExit(f"::error::SELinux policy helper check missing required source: {hooks} or {services}")
h = hooks.read_text()
s = services.read_text()
helper = "security_context_to_sid_with_policy"
body = re.search(r'(?m)^\s*(?:static\s+)?(?:int|void)\s+' + helper + r'\s*\([^;]*\)\s*\{', s)
if body:
    print("SELinux policy-specific context helper implementation exists; leaving hooks.c unchanged")
else:
    standard = "security_context_to_sid"
    header_text = header.read_text() if header.is_file() else ""
    if not re.search(r'\b' + standard + r'\s*\(', s + header_text):
        raise SystemExit(f"::error::Neither {helper} nor standard {standard} API was found; refusing to invent an implementation")

    # Convert only actual six-argument calls. The policy and default SID
    # arguments do not exist in the current-policy API (4 arguments).
    call_pattern = re.compile(r'\b' + helper + r'\s*\(([^()]*)\)')
    converted = [0]
    def split_args(raw):
        parts, begin, depth = [], 0, 0
        for i, ch in enumerate(raw):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif ch == ',' and depth == 0:
                parts.append(raw[begin:i].strip())
                begin = i + 1
        parts.append(raw[begin:].strip())
        return parts
    def replace_call(match):
        line_start = h.rfind('\n', 0, match.start()) + 1
        prefix = h[line_start:match.start()]
        # Leave prototypes/declarations untouched; only rewrite calls.
        if re.search(r'\b(?:extern|static)\s+(?:int|void)\s*$', prefix):
            return match.group(0)
        args = split_args(match.group(1))
        if len(args) != 6:
            return match.group(0)
        converted[0] += 1
        return standard + '(' + ', '.join((args[1], args[2], args[3], args[5])) + ')'
    h2 = call_pattern.sub(replace_call, h)

    # Repair a partially adapted call left by older versions of this script.
    # security_context_to_sid() in this tree takes (context, length, sid, gfp).
    bad_call = re.compile(r'\bsecurity_context_to_sid\s*\(\s*([^,()]+)\s*,\s*([^,()]+)\s*,\s*([^,()]+)\s*,\s*(?:SECSID_NULL|(?:0|SECINITSID_UNLABELED))\s*,\s*(GFP_[A-Z_]+)\s*\)')
    h2, repaired = bad_call.subn(r'security_context_to_sid(\1, \2, \3, \4)', h2)

    # Older regex-based versions could accidentally rename the helper's
    # extern prototype to the incompatible five-argument standard API.
    bad_proto = re.compile(r'(?ms)^[ \t]*extern[ \t]+int[ \t]+security_context_to_sid[ \t]*\([^;]*\b(?:default_sid|SECSID_NULL)\b[^;]*\);[ \t]*\n?')
    h2, removed_proto = bad_proto.subn('', h2)
    helper_proto = re.compile(r'(?ms)^[ \t]*extern[ \t]+int[ \t]+' + helper + r'[ \t]*\([^;]*\);[ \t]*\n?')
    h2, removed_helper_proto = helper_proto.subn('', h2)
    if converted[0] or repaired or removed_proto or removed_helper_proto:
        hooks.write_text(h2)
        print(f"Adapted {converted[0]} policy-specific call(s); repaired {repaired} stale call(s); removed {removed_proto} conflicting standard prototype(s) and {removed_helper_proto} obsolete helper prototype(s) in {hooks.relative_to(root)}")
    elif re.search(r'\b' + helper + r'\s*\([^;]*\)\s*(?!;)', h2):
        raise SystemExit(f"::error::Found an unadapted {helper} call in {hooks}")
    else:
        print("No policy-specific context helper call in hooks.c; nothing to adapt")
PYPOLICY
}

# The SUSFS enable patch is generated against a newer SukiSU revision than the
# pinned source. On the OP13R Android 14 / 6.1 tree, its SELinux-hide hunks can
# reject while the patch driver removes the .rej files and continues. That leaves
# symbols referenced by SELinux core with file-local (static) definitions. Repair
# only those known cross-translation-unit definitions, then verify each one.
repair_selinux_hide_linkage() {
  local root="$1"
  python3 - "$root" <<'PYLINK'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
ksu = root / "drivers/kernelsu/feature/selinux_hide.c"
selinuxfs = root / "security/selinux/selinuxfs.c"
for path in (ksu, selinuxfs):
    if not path.is_file():
        raise SystemExit(f"::error::Required SELinux Hide source missing: {path}")

# These symbols are defined by SukiSU's feature/selinux_hide.c. The SUSFS
# compatibility patch may reject the hunk that removes static linkage, so repair
# the definitions in their owning translation unit rather than duplicating them
# in selinuxfs.c.
s = ksu.read_text()
for pat, repl in [
    (r'(?m)^([\t ]*)static[\t ]+bool[\t ]+ksu_selinux_hide_enabled\b', r'\1bool ksu_selinux_hide_enabled'),
    (r'(?m)^([\t ]*)static[\t ]+bool[\t ]+ksu_selinux_hide_running\b', r'\1bool ksu_selinux_hide_running'),
    (r'(?m)^([\t ]*)static[\t ]+struct[\t ]+selinux_state[\t ]+fake_state[\t ]*;', r'\1struct selinux_state fake_state;'),
    (r'(?m)^([\t ]*)static[\t ]+(DEFINE_STATIC_KEY_FALSE[\t ]*\([\t ]*fake_status_initialize_key[\t ]*\)[\t ]*;)', r'\1\2'),
    (r'(?m)^([\t ]*)static[\t ]+(struct[\t ]+page[\t ]*\*[\t ]*fake_status[\t ]*=)', r'\1\2'),
    (r'(?m)^([\t ]*)static[\t ]+void[\t ]+initialize_fake_status[\t ]*\(', r'\1void initialize_fake_status('),
]:
    s = re.sub(pat, repl, s)
ksu.write_text(s)

# The hide implementation from newer SukiSU revisions may call policy-specific
# helpers that do not exist in older Android SELinux trees. If a helper is absent,
# adapt only its recognized selinuxfs.c call sites to the equivalent current-policy
# API, provided that API exists in this source tree. Do not fail merely because an
# unused compatibility helper is absent.
services = root / "security/selinux/ss/services.c"
header = root / "security/selinux/include/security.h"
if not services.is_file():
    raise SystemExit(f"::error::Required SELinux policy helper source missing: {services}")
sv = services.read_text()
fs = selinuxfs.read_text()
hdr = header.read_text() if header.is_file() else ""

def api_exists(name):
    return bool(re.search(r"\b" + re.escape(name) + r"\s*\(", sv) or
                re.search(r"\b" + re.escape(name) + r"\s*\(", hdr))

def split_args(raw):
    parts, begin, depth = [], 0, 0
    for i, ch in enumerate(raw):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(raw[begin:i].strip())
            begin = i + 1
    parts.append(raw[begin:].strip())
    return parts

def replace_policy_call_args(source, old, new):
    # Convert complete calls, preserving balanced parentheses. The policy
    # parameter is removed from all three APIs; context-to-SID also drops the
    # obsolete default-SID argument because current API takes four arguments.
    token = re.compile(r"\b" + re.escape(old) + r"\s*\(")
    out = []
    pos = 0
    count = 0
    while True:
        match = token.search(source, pos)
        if not match:
            out.append(source[pos:])
            break
        out.append(source[pos:match.start()])
        open_paren = source.find("(", match.start(), match.end())
        depth = 1
        i = open_paren + 1
        while i < len(source) and depth:
            ch = source[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth != 0:
            out.append(source[match.start():match.end()])
            pos = match.end()
            continue
        args = split_args(source[open_paren + 1:i - 1])
        # Do not rewrite prototypes, malformed calls, or unexpected signatures.
        line_start = source.rfind("\n", 0, match.start()) + 1
        prefix = source[line_start:match.start()]
        if re.search(r"\b(?:extern|static)\s+(?:int|void)\s*$", prefix):
            out.append(source[match.start():i])
            pos = i
            continue
        if old == "security_context_to_sid_with_policy" and len(args) == 6:
            args = [args[1], args[2], args[3], args[5]]
        elif old in ("security_sid_to_context_with_policy", "security_compute_av_user_with_policy") and len(args) in (4, 5):
            args = args[1:]
        else:
            out.append(source[match.start():i])
            pos = i
            continue
        out.append(new + "(" + ", ".join(args) + ")")
        count += 1
        pos = i
    return "".join(out), count

policy_helpers = (
    ("security_context_to_sid_with_policy", "security_context_to_sid"),
    ("security_sid_to_context_with_policy", "security_sid_to_context"),
    ("security_compute_av_user_with_policy", "security_compute_av_user"),
)
for old, current_api in policy_helpers:
    definition = re.search(r"\b" + re.escape(old) + r"\s*\([^;{}]*\)\s*\{", sv, re.S)
    if definition:
        line_start = sv.rfind("\n", 0, definition.start()) + 1
        line_end = sv.find("\n", definition.start())
        if line_end < 0:
            line_end = len(sv)
        first_line = sv[line_start:line_end]
        if re.match(r"^[\t ]*static\b", first_line):
            sv = sv[:line_start] + re.sub(r"^([\t ]*)static[\t ]+", r"\1", first_line, count=1) + sv[line_end:]
            print(f"Removed file-local static linkage from {old} in {services.relative_to(root)}")
        continue

    if re.search(r"\b" + re.escape(old) + r"\s*\(", fs):
        if not api_exists(current_api):
            raise SystemExit(f"::error::SELinux helper {old} is absent and compatible API {current_api} was not found; refusing unsafe rewrite")
        fs2, count = replace_policy_call_args(fs, old, current_api)
        if count == 0:
            raise SystemExit(f"::error::Found {old} consumer in {selinuxfs}, but could not safely adapt its arguments")
        fs = fs2
        print(f"Adapted {count} selinuxfs.c call(s): {old} -> {current_api}")
    else:
        print(f"SELinux helper {old} is absent but unused in selinuxfs.c; no compatibility change needed")

selinuxfs.write_text(fs)
services.write_text(sv)
# Validate only consumers that actually exist in this kernel revision.
# Newer OnePlus/Android 16 trees may not use selinuxfs.c for the fake-status
# implementation; requiring every legacy identifier in that file rejects a
# valid tree before compilation. Keep ownership of the fake-status symbols in
# selinux_hide.c and inspect known SELinux integration files without injecting
# duplicate declarations or function bodies.
fs = selinuxfs.read_text()
services = root / "security/selinux/ss/services.c"
consumer_files = [selinuxfs]
if services.is_file():
    consumer_files.append(services)
found_consumers = []
for path in consumer_files:
    content = path.read_text()
    symbols = [symbol for symbol in ("fake_status_initialize_key", "fake_status", "initialize_fake_status") if symbol in content]
    if symbols:
        found_consumers.append(f"{path.relative_to(root)}: {', '.join(symbols)}")

print(f"Fixed SELinux Hide cross-file linkage: {ksu.relative_to(root)}")
if found_consumers:
    print("Validated SELinux Hide consumer references: " + " | ".join(found_consumers))
else:
    print("No legacy fake-status consumers found in selinuxfs.c/services.c; keeping symbol definitions in selinux_hide.c")

checks = {
    ksu: [
        r'(?m)^[\t ]*bool[\t ]+ksu_selinux_hide_enabled\b',
        r'(?m)^[\t ]*bool[\t ]+ksu_selinux_hide_running\b',
        r'(?m)^[\t ]*struct[\t ]+selinux_state[\t ]+fake_state[\t ]*;',
        r'(?m)^[\t ]*DEFINE_STATIC_KEY_FALSE[\t ]*\([\t ]*fake_status_initialize_key[\t ]*\)[\t ]*;',
        r'(?m)^[\t ]*struct[\t ]+page[\t ]*\*[\t ]*fake_status[\t ]*=',
        r'(?m)^[\t ]*void[\t ]+initialize_fake_status[\t ]*\(',
    ],
}
for path, patterns in checks.items():
    content = path.read_text()
    for pattern in patterns:
        if not re.search(pattern, content):
            raise SystemExit(f"::error::SELinux Hide global definition missing after repair: {path} / {pattern}")
print("SELinux Hide cross-file symbol definitions validated")
PYLINK
}

patch_lsm_hook "$KSU_FOLDER/kernel/hook/lsm_hook.c"
patch_lsm_hook "$COMMON_KERNEL_FOLDER/drivers/kernelsu/hook/lsm_hook.c"
repair_missing_policy_context_helper "$COMMON_KERNEL_FOLDER"
repair_selinux_hide_linkage "$COMMON_KERNEL_FOLDER"
repair_selinux_hide_late_hooks() {
  local root="$1"
  python3 - "$root" <<'PYLATE'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
hide = root / "drivers/kernelsu/feature/selinux_hide.c"
ksud = root / "drivers/kernelsu/runtime/ksud_integration.c"
boot = root / "drivers/kernelsu/runtime/boot_event.c"
if not hide.is_file():
    raise SystemExit(f"::error::SELinux Hide source missing: {hide}")
s = hide.read_text()
# The current SUSFS patch replaces the old status-open fops hook with the
# fake-status-page/static-key implementation. Remove stale declaration/call
# only when the hook has no function body in this source.
if not re.search(r'(?m)^\s*(?:static\s+)?(?:int|void)\s+hook_selinux_status_open\s*\([^;]*\)\s*\{', s):
    s = re.sub(r'(?m)^\s*static\s+void\s+hook_selinux_status_open\s*\([^;]*\)\s*;\s*\n', '', s)
    s = re.sub(r'(?m)^\s*hook_selinux_status_open\s*\(\s*\)\s*;\s*\n', '', s)

# The newer SUSFS integration calls these two lifecycle callbacks. Older
# SukiSU snapshots may not contain their definitions even though call sites
# were patched in. Implement the callbacks using the fake-status API already
# owned by selinux_hide.c; do not stub them out.
if 'ksu_selinux_hide_handle_second_stage' not in s:
    if 'initialize_fake_status' not in s or 'fake_status_initialize_key' not in s or 'fake_status' not in s:
        raise SystemExit(f"::error::Cannot safely add second-stage SELinux Hide callback in {hide}: fake-status implementation missing")
    s += "\n\nvoid ksu_selinux_hide_handle_second_stage(void)\n{\n    initialize_fake_status();\n    if (fake_status)\n        static_key_disable(&fake_status_initialize_key.key);\n    else\n        pr_warn(\"selinux_hide: fake status need late initialization\\n\");\n}\n"
if 'ksu_selinux_hide_handle_post_fs_data' not in s:
    if 'fake_status_initialize_key' not in s or 'fake_status' not in s:
        raise SystemExit(f"::error::Cannot safely add post-fs-data SELinux Hide callback in {hide}: fake-status implementation missing")
    s += "\n\nvoid ksu_selinux_hide_handle_post_fs_data(void)\n{\n    static_key_disable(&fake_status_initialize_key.key);\n    if (!fake_status)\n        pr_err(\"selinux_hide: fake status is not initialized after post-fs-data!\\n\");\n}\n"
hide.write_text(s)
for name in ('ksu_selinux_hide_handle_second_stage', 'ksu_selinux_hide_handle_post_fs_data'):
    if len(re.findall(r'(?m)^\s*void\s+' + name + r'\s*\(', s)) != 1:
        raise SystemExit(f"::error::Expected exactly one definition of {name} in {hide}")
for path, name in ((ksud, 'ksu_selinux_hide_handle_second_stage'), (boot, 'ksu_selinux_hide_handle_post_fs_data')):
    if path.is_file() and name in path.read_text() and name not in s:
        raise SystemExit(f"::error::Missing implementation for {name} referenced by {path}")
if re.search(r'(?m)^\s*static\s+void\s+hook_selinux_status_open\s*\(', s) and not re.search(r'(?m)^\s*(?:static\s+)?(?:int|void)\s+hook_selinux_status_open\s*\([^;]*\)\s*\{', s):
    raise SystemExit(f"::error::Stale hook_selinux_status_open declaration remains in {hide}")
print(f"Repaired SELinux Hide lifecycle callbacks and stale status-hook reference in {hide}")
PYLATE
}

repair_selinux_hide_late_hooks "$COMMON_KERNEL_FOLDER"

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
echo "  SELinux Hide cross-file linkage: verified"
