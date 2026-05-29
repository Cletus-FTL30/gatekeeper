import yaml

rule_path = "rules/baseline/proc_creation_win_susp_whoami_as_param.yml"

with open(rule_path) as f:
    rule = yaml.safe_load(f)

print("Title:    ", rule["title"])
print("ID:       ", rule["id"])
print("Logsource:", rule["logsource"])
print("Detection:", rule["detection"])
print("Condition:", rule["detection"]["condition"])
print("Level:    ", rule["level"])
