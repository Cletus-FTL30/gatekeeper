import yaml

baseline_path = "rules/baseline/proc_creation_win_susp_whoami_as_param.yml"
modified_path = "rules/modified/drift_whoami_logsource.yml"

with open(baseline_path) as f:
    baseline = yaml.safe_load(f)

with open(modified_path) as f:
    modified = yaml.safe_load(f)

baseline_logsource = baseline["logsource"]
modified_logsource = modified["logsource"]

print("Baseline logsource:", baseline_logsource)
print("Modified logsource:", modified_logsource)
print()

if baseline_logsource == modified_logsource:
    print("[NO CHANGE] The logsource is the same.")
else:
    print("[WEAKENING] Log-source drift detected.")
    print("    The rule now watches a different data source, so it may miss what it used to catch.")
    for key in baseline_logsource:
        old_value = baseline_logsource.get(key)
        new_value = modified_logsource.get(key)
        if old_value != new_value:
            print(f"    {key}: '{old_value}' -> '{new_value}'")
