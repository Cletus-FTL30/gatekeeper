import yaml

baseline_path = "rules/baseline/proc_creation_win_netsh_port_forwarding.yml"
modified_path = "rules/modified/proc_creation_win_netsh_port_forwarding.yml"

with open(baseline_path) as f:
    baseline = yaml.safe_load(f)

with open(modified_path) as f:
    modified = yaml.safe_load(f)

baseline_detection = baseline["detection"]
modified_detection = modified["detection"]

baseline_condition = baseline_detection["condition"]
modified_condition = modified_detection["condition"]

baseline_keys = set(baseline_detection.keys())
modified_keys = set(modified_detection.keys())
new_keys = modified_keys - baseline_keys

print("Baseline condition:", baseline_condition)
print("Modified condition:", modified_condition)
print("New detection blocks added:", new_keys)
print()

added_not = "not" in modified_condition and "not" not in baseline_condition

if new_keys or added_not:
    print("[WEAKENING] Added exclusion detected.")
    if new_keys:
        print(f"    New filter block(s) added: {new_keys}")
    if added_not:
        print("    The condition now excludes something it did not before (added 'not').")
    print("    This may create a blind spot the rule used to catch.")
else:
    print("[NO CHANGE] No added exclusion found.")
