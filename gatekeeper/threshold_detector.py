import yaml
import re

baseline_path = "rules/baseline/test_threshold_failed_logins.yml"
modified_path = "rules/modified/test_threshold_failed_logins.yml"

with open(baseline_path) as f:
    baseline = yaml.safe_load(f)

with open(modified_path) as f:
    modified = yaml.safe_load(f)

baseline_condition = baseline["detection"]["condition"]
modified_condition = modified["detection"]["condition"]

def get_threshold(condition):
    match = re.search(r">\s*(\d+)", condition)
    if match:
        return int(match.group(1))
    return None

baseline_threshold = get_threshold(baseline_condition)
modified_threshold = get_threshold(modified_condition)

print("Baseline threshold:", baseline_threshold)
print("Modified threshold:", modified_threshold)
print()

if baseline_threshold is None or modified_threshold is None:
    print("[NO THRESHOLD] Could not find a threshold to compare.")
elif modified_threshold == baseline_threshold:
    print("[NO CHANGE] The threshold is the same.")
elif modified_threshold > baseline_threshold:
    print("[WEAKENING] Threshold inflation detected.")
    print(f"    Threshold raised from {baseline_threshold} to {modified_threshold} - the rule now fires less often.")
else:
    print("[STRONGER] Threshold lowered - the rule now fires more easily.")
