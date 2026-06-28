import yaml

baseline_path = "rules/baseline/test_condition_logic.yml"
modified_path = "rules/modified/test_condition_logic.yml"

with open(baseline_path) as f:
    baseline = yaml.safe_load(f)

with open(modified_path) as f:
    modified = yaml.safe_load(f)

baseline_condition = baseline["detection"]["condition"]
modified_condition = modified["detection"]["condition"]

print("Baseline condition:", baseline_condition)
print("Modified condition:", modified_condition)
print()

logic_words = ["and", "or", "all of", "1 of", "not"]

baseline_logic = [word for word in logic_words if word in baseline_condition]
modified_logic = [word for word in logic_words if word in modified_condition]

if baseline_condition == modified_condition:
    print("[NO CHANGE] The condition is the same.")
elif baseline_logic != modified_logic:
    print("[WEAKENING] Condition logic changed - flagged for review.")
    print(f"    Baseline logic: {baseline_logic}")
    print(f"    Modified logic: {modified_logic}")
    print("    A change in condition logic can alter how often the rule fires.")
    print("    A human should review whether this strengthens or weakens detection.")
else:
    print("[CHANGE] The condition changed but the core logic words are the same.")
