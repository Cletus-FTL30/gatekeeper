import os
import random
import yaml
import csv
import copy
import re
import uuid

POOL = os.path.expanduser("~/sigma-source/rules/windows/process_creation")
SEED = 42
SAMPLE_SIZE = 20

all_files = sorted(f for f in os.listdir(POOL) if f.endswith(".yml"))
random.seed(SEED)
sampled = random.sample(all_files, SAMPLE_SIZE)

MATCH_MODIFIERS = ("|contains", "|endswith", "|startswith")


def _is_match_key(key):
    return any(m in key for m in MATCH_MODIFIERS)


# ---------- WEAKENING TRANSFORMATIONS (expected_flag = yes) ----------

def narrow_match(rule):
    modified = copy.deepcopy(rule)
    for block_name, block in modified.get("detection", {}).items():
        if block_name == "condition":
            continue
        candidates = block if isinstance(block, list) else [block]
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            for key, value in candidate.items():
                if _is_match_key(key) and isinstance(value, str):
                    candidate[key] = "\\Windows\\System32" + value
                    return modified
    return None


def drift_logsource(rule):
    modified = copy.deepcopy(rule)
    logsource = modified.get("logsource", {})
    if "category" not in logsource:
        return None
    logsource["category"] = "file_event" if logsource["category"] == "process_creation" else "process_creation"
    return modified


def add_exclusion(rule):
    modified = copy.deepcopy(rule)
    detection = modified.get("detection", {})
    condition = detection.get("condition")
    if not isinstance(condition, str) or "gk_filter" in condition:
        return None
    detection["gk_filter"] = {"CommandLine|contains": "-ExecutionPolicy Bypass"}
    detection["condition"] = f"({condition}) and not gk_filter"
    return modified


def weaken_condition(rule):
    modified = copy.deepcopy(rule)
    detection = modified.get("detection", {})
    condition = detection.get("condition")
    if not isinstance(condition, str):
        return None
    if "all of" in condition:
        detection["condition"] = condition.replace("all of", "1 of")
        return modified
    if " and " in condition:
        detection["condition"] = condition.replace(" and ", " or ")
        return modified
    return None


def inflate_threshold(rule):
    modified = copy.deepcopy(rule)
    detection = modified.get("detection", {})
    condition = detection.get("condition")
    if not isinstance(condition, str):
        return None
    match = re.search(r">\s*(\d+)", condition)
    if not match:
        return None
    new_value = int(match.group(1)) * 100
    detection["condition"] = condition.replace(match.group(0), f"> {new_value}", 1)
    return modified


# ---------- NON-WEAKENING TRANSFORMATIONS (expected_flag = no) ----------

def unchanged(rule):
    """No change at all. The tool must not flag this."""
    return copy.deepcopy(rule)


def cosmetic_edit(rule):
    """Edit only the description. Detection logic is untouched."""
    modified = copy.deepcopy(rule)
    if "description" not in modified:
        return None
    modified["description"] = modified["description"] + " Reviewed and updated for clarity."
    return modified


def strengthen(rule):
    """Add an extra match value so the rule catches MORE than before."""
    modified = copy.deepcopy(rule)
    for block_name, block in modified.get("detection", {}).items():
        if block_name == "condition":
            continue
        candidates = block if isinstance(block, list) else [block]
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            for key, value in candidate.items():
                if _is_match_key(key) and isinstance(value, str):
                    candidate[key] = [value, value.replace(".exe", "_backup.exe")]
                    return modified
    return None


# ---------- GENERATION ----------

TRANSFORMATIONS = [
    ("narrowed_match",      narrow_match,      "yes"),
    ("logsource_drift",     drift_logsource,   "yes"),
    ("added_exclusion",     add_exclusion,     "yes"),
    ("weakened_condition",  weaken_condition,  "yes"),
    ("threshold_inflation", inflate_threshold, "yes"),
    ("unchanged",           unchanged,         "no"),
    ("cosmetic_edit",       cosmetic_edit,     "no"),
    ("strengthened",        strengthen,        "no"),
]

OUT_DIR = os.path.expanduser("~/gatekeeper/evaluation_generated")
BASELINE_DIR = os.path.join(OUT_DIR, "baseline")
MODIFIED_DIR = os.path.join(OUT_DIR, "modified")
CSV_PATH = os.path.join(OUT_DIR, "evaluation_set.csv")

os.makedirs(BASELINE_DIR, exist_ok=True)
os.makedirs(MODIFIED_DIR, exist_ok=True)

rows = []
skipped = {}
pair_number = 0

for source_file in sampled:
    with open(os.path.join(POOL, source_file)) as f:
        baseline = yaml.safe_load(f)

    if not isinstance(baseline, dict) or "detection" not in baseline:
        continue

    for pattern_name, transform, expected in TRANSFORMATIONS:
        result = transform(baseline)

        if result is None:
            skipped[pattern_name] = skipped.get(pattern_name, 0) + 1
            continue

        pair_number += 1
        pair_id = f"gen{pair_number:03d}"
        rule_name = f"{pair_id}_{pattern_name}"

# Give each PAIR its own identity so variants of the same source rule
        # do not collide, while baseline and modified stay matched to each other.
        pair_uuid = str(uuid.uuid4())
        baseline = copy.deepcopy(baseline)
        baseline["id"] = pair_uuid
        baseline["title"] = f"{baseline.get('title', 'Untitled')} [{pair_id}]"
        result["id"] = pair_uuid
        result["title"] = baseline["title"]
        with open(os.path.join(BASELINE_DIR, rule_name + ".yml"), "w") as f:
            yaml.dump(baseline, f, sort_keys=False, allow_unicode=True)
        with open(os.path.join(MODIFIED_DIR, rule_name + ".yml"), "w") as f:
            yaml.dump(result, f, sort_keys=False, allow_unicode=True)

        rows.append({
            "pair_id": pair_id,
            "rule_name": rule_name,
            "pattern": pattern_name,
            "change_type": "weakened" if expected == "yes" else "not_weakened",
            "expected_flag": expected,
            "source_rule": source_file,
        })

with open(CSV_PATH, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=[
        "pair_id", "rule_name", "pattern", "change_type", "expected_flag", "source_rule"
    ])
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated {len(rows)} pairs from {len(sampled)} source rules\n")

counts = {}
for r in rows:
    counts[r["pattern"]] = counts.get(r["pattern"], 0) + 1

print("Pairs per pattern:")
for name, _, expected in TRANSFORMATIONS:
    made = counts.get(name, 0)
    missed = skipped.get(name, 0)
    print(f"  {name:<20} {made:>3}  (skipped {missed}, expected_flag={expected})")

positives = sum(1 for r in rows if r["expected_flag"] == "yes")
print(f"\nPositives (should flag): {positives}")
print(f"Negatives (should not) : {len(rows) - positives}")
print(f"\nWritten to {OUT_DIR}")
