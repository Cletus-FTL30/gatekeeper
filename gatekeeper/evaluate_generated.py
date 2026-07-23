import yaml
import re

def load_rule(path):
    with open(path) as f:
        return yaml.safe_load(f)

def is_weakened(baseline, modified):
    reasons = []

    b_det = baseline.get("detection", {})
    m_det = modified.get("detection", {})
    b_cond = str(b_det.get("condition", ""))
    m_cond = str(m_det.get("condition", ""))

    # PATTERN 3: log-source drift (dictionary comparison)
    if baseline.get("logsource") != modified.get("logsource"):
        reasons.append("logsource_drift")

    # PATTERN 2: threshold inflation (number after '>')
    b_thr = re.search(r">\s*(\d+)", b_cond)
    m_thr = re.search(r">\s*(\d+)", m_cond)
    if b_thr and m_thr and int(m_thr.group(1)) > int(b_thr.group(1)):
        reasons.append("threshold_inflation")

    # PATTERN 4: added exclusion (new detection block OR added 'not')
    new_keys = set(m_det.keys()) - set(b_det.keys())
    if new_keys or ("not" in m_cond and "not" not in b_cond):
        reasons.append("added_exclusion")

    # PATTERN 5: weakened condition (logic operators changed)
    logic_words = ["and", "or", "all of", "1 of", "not"]
    b_logic = [w for w in logic_words if w in b_cond]
    m_logic = [w for w in logic_words if w in m_cond]
    if b_cond != m_cond and b_logic != m_logic:
        reasons.append("condition_change")

    # PATTERN 1: narrowed match (a baseline string now longer/more specific)
    b_str = yaml.dump(b_det)
    m_str = yaml.dump(m_det)
    if b_str != m_str and "logsource_drift" not in reasons:
        # crude: modified detection text differs; flag for review
        if len(m_str) != len(b_str):
            reasons.append("possible_narrowed_or_changed_match")

    return (len(reasons) > 0, reasons)

import csv

TP = FP = TN = FN = 0
results = []

with open("evaluation_generated/evaluation_set.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        name = row["rule_name"]
        expected_yes = row["expected_flag"].strip().lower() == "yes"

        baseline = load_rule(f"evaluation_generated/baseline/{name}.yml")
        modified = load_rule(f"evaluation_generated/modified/{name}.yml")
        flagged, reasons = is_weakened(baseline, modified)

        if flagged and expected_yes:
            outcome = "TP"; TP += 1
        elif flagged and not expected_yes:
            outcome = "FP"; FP += 1
        elif not flagged and not expected_yes:
            outcome = "TN"; TN += 1
        else:
            outcome = "FN"; FN += 1

        results.append((row["pair_id"], name, "FLAG" if flagged else "pass", outcome))

print(f"{'ID':<4}{'RULE':<28}{'RESULT':<8}{'OUTCOME'}")
print("-" * 55)
for pid, name, res, outcome in results:
    print(f"{pid:<4}{name:<28}{res:<8}{outcome}")

print()
print(f"TP={TP}  FP={FP}  TN={TN}  FN={FN}")

precision = TP / (TP + FP) if (TP + FP) else 0
recall = TP / (TP + FN) if (TP + FN) else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

print()
print(f"Precision: {precision:.2f}")
print(f"Recall:    {recall:.2f}")
print(f"F1 score:  {f1:.2f}")
