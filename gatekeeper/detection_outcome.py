# Match values from the Sigma to Splunk conversion
# Original rule: CommandLine="*.exe whoami*"
# Weakened rule: CommandLine="*cmd.exe whoami*"
# Splunk matches any command line containing this value

original_match = ".exe whoami"
weakened_match = "cmd.exe whoami"

# Sample log events (representing real command lines an attacker might run)
log_events = [
    "cmd.exe whoami",
    "powershell.exe whoami",
    "wmic.exe whoami",
    "pwsh.exe whoami",
]

print("Testing log events against the original and weakened rules.")
print(f"  Original catches anything containing: '{original_match}'")
print(f"  Weakened catches anything containing: '{weakened_match}'")
print()

missed = []

for event in log_events:
    caught_by_original = original_match in event
    caught_by_weakened = weakened_match in event

    if caught_by_original and not caught_by_weakened:
        status = "MISSED by weakened rule"
        missed.append(event)
    elif caught_by_original and caught_by_weakened:
        status = "caught by both"
    else:
        status = "not caught by either"

    print(f"  {event:<28} -> {status}")

print()
if missed:
    print(f"[COVERAGE LOSS] The weakened rule misses {len(missed)} event(s) the original catches:")
    for event in missed:
        print(f"    - {event}")
    print("    These are real attacks the original rule would detect but the weakened rule would not.")
else:
    print("[NO COVERAGE LOSS] The weakened rule catches everything the original does.")
