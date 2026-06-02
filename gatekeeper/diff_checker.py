import yaml

baseline_path = "rules/baseline/proc_creation_win_susp_whoami_as_param.yml"
modified_path = "rules/modified/proc_creation_win_susp_whoami_as_param.yml"

with open(baseline_path) as f:
    baseline = yaml.safe_load(f)

with open(modified_path) as f:
    modified = yaml.safe_load(f)

fields_to_check = ["title", "logsource", "detection", "condition", "level"]

print("Comparing rules...")
print()

for field in fields_to_check:
    baseline_value = baseline.get(field)
    modified_value = modified.get(field)

    if baseline_value == modified_value:
        print(f"[SAME] {field}")
    else:
        print(f"[DIFFERENT] {field}")
        print(f"    baseline: {baseline_value}")
        print(f"    modified: {modified_value}")
