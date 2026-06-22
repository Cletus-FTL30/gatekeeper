import subprocess

rule_path = "rules/modified/proc_creation_win_susp_whoami_as_param.yml"

print("Running official Sigma validator on:", rule_path)
print()

result = subprocess.run(
    ["sigma", "check", rule_path],
    capture_output=True,
    text=True
)

print(result.stdout)

if result.returncode == 0:
    print("[VALID] The rule passes official Sigma validation.")
else:
    print("[INVALID] The rule failed official Sigma validation.")
