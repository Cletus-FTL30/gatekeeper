import yaml

baseline_path = "rules/baseline/proc_creation_win_susp_whoami_as_param.yml"
modified_path = "rules/modified/proc_creation_win_susp_whoami_as_param.yml"

with open(baseline_path) as f:
    baseline = yaml.safe_load(f)

with open(modified_path) as f:
    modified = yaml.safe_load(f)

baseline_value = baseline["detection"]["selection"]["CommandLine|contains"]
modified_value = modified["detection"]["selection"]["CommandLine|contains"]

print("Baseline match value:", baseline_value)
print("Modified match value:", modified_value)
print()

if baseline_value == modified_value:
    print("[NO CHANGE] The match value is the same.")
elif baseline_value in modified_value:
    print("[WEAKENING] Narrowed match detected.")
    print("    The new value is more specific, so the rule catches less.")
else:
    print("[CHANGE] The match value changed, but it is not a simple narrowing.")
