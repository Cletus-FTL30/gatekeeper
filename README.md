 #Gatekeeper: Detecting Semantic Weakening in Detection-as Code Rules using a CI/CD Integrity Gate

GateKeeper is a proof-of-concept pre-deployment CI/CD integrity gate for Detection-as-Code workflows using Sigma rules.

It compares a modified Sigma rule with its baseline version and identifies changes that may weaken the rule's intended detection behaviour even when the modified rule remains structurally valid and continues to pass `sigma check`.

The repository contains the GateKeeper prototype, two evaluation datasets, evaluation scripts, saved results, and a local SIEM testbed used to examine the effect of rule changes on detection coverage.

This project was developed as part of an MSc Cyber Security dissertation at the University of the West of England (UWE), Bristol.

---

## The Problem

Detection-as-Code allows detection rules to be managed using software engineering practices such as version control, pull requests, automated testing, and CI/CD pipelines.

These controls are useful for checking whether a rule is syntactically and structurally valid. However, a rule can still pass those checks after a change that alters its intended security behaviour.

For example, a modification may:

- make a match more restrictive;
- increase a detection threshold;
- change the expected log source;
- introduce an exclusion that suppresses relevant events; or
- alter the rule condition.

GateKeeper adds an additional integrity check before deployment by comparing the baseline and modified rules and identifying changes that may represent semantic weakening.

---

## Weakening Patterns

The prototype evaluates five categories of rule change:

| Pattern | Description |
| --- | --- |
| **Narrowed match** | A match value becomes more specific, reducing the events matched by the rule. |
| **Threshold inflation** | A counting threshold is increased, causing the rule to trigger less frequently. |
| **Log-source drift** | The modified rule points to a different or unexpected data source. |
| **Added exclusion** | A new filter or exclusion suppresses events that were previously detected. |
| **Condition change** | Detection-condition logic is altered in a way that may weaken the intended rule semantics. |

GateKeeper also evaluates non-weakening changes, including unchanged rules, legitimate modifications, cosmetic edits, and strengthened rules, to determine whether the system can distinguish weakening from harmless changes.

---

## How GateKeeper Works

```text
Baseline Sigma rule
        │
        ├──────────────┐
        │              │
        ▼              ▼
Modified Sigma rule   sigma check
        │
        ▼
Structural comparison
        │
        ▼
Weakening detectors
        │
        ├── Narrowed match
        ├── Threshold inflation
        ├── Log-source drift
        ├── Added exclusion
        └── Condition change
        │
        ▼
Rule-based / LLM-assisted / Hybrid review
        │
        ▼
Pre-deployment decision
```

The rule-based implementation performs deterministic checks for known weakening patterns. The LLM-assisted implementation reviews the semantic difference between the baseline and modified rule. The hybrid approach combines both methods, using the rule-based stage to handle straightforward cases before escalating selected cases for LLM review.

---

## Repository Structure

| Path | Purpose |
| --- | --- |
| `gatekeeper/rule_reader.py` | Loads Sigma YAML rules into Python. |
| `gatekeeper/diff_checker.py` | Compares baseline and modified rules field by field. |
| `gatekeeper/validator.py` | Runs Sigma CLI validation using `sigma check`. |
| `gatekeeper/weakening_detector.py` | Detects narrowed-match changes. |
| `gatekeeper/threshold_detector.py` | Detects threshold inflation. |
| `gatekeeper/logsource_detector.py` | Detects log-source drift. |
| `gatekeeper/exclusion_detector.py` | Detects added exclusions. |
| `gatekeeper/condition_detector.py` | Detects condition changes associated with weakening. |
| `gatekeeper/detection_outcome.py` | Demonstrates the detection effect of a weakened rule. |
| `gatekeeper/evaluate.py` | Runs rule-based evaluation on the 10-pair hand-built dataset. |
| `gatekeeper/evaluate_generated.py` | Runs rule-based evaluation on the 125-pair generated dataset. |
| `gatekeeper/generate_pairs.py` | Generates the 125-pair dataset from sampled SigmaHQ rules. |
| `gatekeeper/llm_reviewer.py` | Runs LLM-assisted review on the hand-built dataset. |
| `gatekeeper/llm_generated.py` | Runs LLM-assisted review on the generated dataset. |
| `gatekeeper/llm_variance.py` | Tests consistency across repeated LLM reviews. |
| `gatekeeper/hybrid_reviewer.py` | Runs hybrid review on the hand-built dataset. |
| `gatekeeper/hybrid_generated.py` | Runs hybrid review on the generated dataset. |
| `evaluation/` | Hand-built dataset containing 10 baseline-modified rule pairs. |
| `evaluation_generated/` | Generated dataset containing 125 baseline-modified rule pairs. |
| `testbed/load_logs.py` | Loads test events into a local Elasticsearch instance. |
| `testbed/run_testbed.py` | Compares original and weakened rule outcomes against the test events. |
| `results/` | Saved evaluation results, charts, and summary outputs. |
| `DATASET_VERSION.md` | Records the pinned SigmaHQ dataset version used for reproducibility. |

---

## Evaluation Datasets

### Hand-built dataset

The `evaluation/` directory contains **10 baseline-modified Sigma rule pairs**:

```text
evaluation/
├── baseline/
├── modified/
└── evaluation_set.csv
```

The set contains both weakening and non-weakening examples, allowing the prototype to be tested on its ability to detect weakening while avoiding incorrect flags on legitimate changes.

### Generated dataset

The `evaluation_generated/` directory contains **125 baseline-modified rule pairs** generated from **20 sampled SigmaHQ rules**:

```text
evaluation_generated/
├── baseline/
├── modified/
└── evaluation_set.csv
```

The generator uses a sorted source-file list together with `random.seed(42)` to make the sampling process reproducible.

The SigmaHQ source dataset is pinned to commit:

```text
994da16651194500b607a3007186c29779e1f961
```

See `DATASET_VERSION.md` for dataset provenance information.

---

## Requirements

The prototype was developed and tested using:

- Ubuntu 24 under VMware
- Python 3.12
- Sigma CLI
- PyYAML
- Elasticsearch 8.15 for the SIEM testbed
- Anthropic API access for LLM-assisted and hybrid experiments

Elasticsearch is only required for the SIEM testbed.

The API key is only required for experiments involving LLM review. The rule-based detectors can run independently.

A local SigmaHQ clone is only required if the generated dataset needs to be regenerated. The generated dataset used in the evaluation is already included in this repository.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/Cletus-FTL30/gatekeeper.git
cd gatekeeper
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install pyyaml sigma-cli anthropic elasticsearch
```

Install the Sigma backends used by the project:

```bash
sigma plugin install splunk
sigma plugin install elasticsearch
```

### 4. Configure the API key

This step is only required for the LLM-assisted and hybrid experiments.

```bash
export ANTHROPIC_API_KEY="your-key-here"
```

To confirm the variable is set without exposing the full key:

```bash
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "ANTHROPIC_API_KEY is set"
else
    echo "ANTHROPIC_API_KEY is not set"
fi
```

The API key is read from the environment and is not stored in the repository.

---

## Reproducing the Experiments

### 1. Demonstrate the core problem

Confirm that a modified rule can remain structurally valid:

```bash
sigma check rules/modified/proc_creation_win_susp_whoami_as_param.yml
```

Then run the GateKeeper evaluation:

```bash
python3 gatekeeper/evaluate.py
```

This demonstrates the central problem addressed by the project: structural validation alone does not determine whether a rule modification preserved its intended detection behaviour.

### 2. Rule-based evaluation

Hand-built dataset:

```bash
python3 gatekeeper/evaluate.py
```

Generated dataset:

```bash
python3 gatekeeper/evaluate_generated.py
```

### 3. LLM-assisted evaluation

These experiments require `ANTHROPIC_API_KEY`.

Hand-built dataset:

```bash
python3 gatekeeper/llm_reviewer.py
```

Generated dataset:

```bash
python3 gatekeeper/llm_generated.py
```

Consistency test:

```bash
python3 gatekeeper/llm_variance.py
```

### 4. Hybrid evaluation

Hand-built dataset:

```bash
python3 gatekeeper/hybrid_reviewer.py
```

Generated dataset:

```bash
python3 gatekeeper/hybrid_generated.py
```

### 5. Regenerate the generated dataset

This step is optional because the generated dataset is already included in the repository.

```bash
git clone https://github.com/SigmaHQ/sigma.git ~/sigma-source
cd ~/sigma-source
git checkout 994da16651194500b607a3007186c29779e1f961
cd -
python3 gatekeeper/generate_pairs.py
```

The generator uses a sorted file list and:

```python
random.seed(42)
```

to reproduce the same sampling process.

### 6. Run the SIEM testbed

Start Elasticsearch:

```bash
~/elasticsearch-8.15.0/bin/elasticsearch
```

In a second terminal:

```bash
source venv/bin/activate
python3 testbed/load_logs.py
python3 testbed/run_testbed.py
```

The testbed compares the detection outcome of an original rule with its weakened version against controlled test events.

---

## Results

### Hand-built dataset

| Approach | Precision | Recall | F1-score |
| --- | ---: | ---: | ---: |
| Rule-based | 88% | 100% | 93% |
| LLM-assisted | 100% | 86% | 92% |
| **Hybrid** | **100%** | **100%** | **100%** |

### Generated dataset

| Approach | Precision | Recall | F1-score |
| --- | ---: | ---: | ---: |
| Rule-based | 82% | 100% | 90% |
| LLM-assisted | 100% | 100% | 100% |
| **Hybrid** | **100%** | **100%** | **100%** |

Full per-pair results are available in `results/`.

---

## Key Findings

- The rule-based approach achieved **100% recall on both datasets**.
- On the generated dataset, all **15 false positives were strengthened rules**, showing that deterministic checks can detect significant change but may not always determine the direction of that change.
- The LLM-assisted approach achieved perfect performance on the generated dataset but missed a subtler condition-related case in the hand-built set.
- The hybrid approach achieved **100% precision, recall, and F1-score on both datasets**.
- On the generated dataset, the hybrid approach required LLM review for **85 of 125 pairs**, approximately **32% fewer LLM calls** than reviewing every pair with the LLM alone.
- In the SIEM testbed, the original `whoami` rule detected **4/4 attacker events**, while the weakened rule detected **1/4**.

These results are proof-of-concept findings and should not be interpreted as general performance claims across all Sigma rules or production Detection-as-Code environments.

---

## Reproducibility

| Item | Configuration |
| --- | --- |
| SigmaHQ version | `994da16651194500b607a3007186c29779e1f961` |
| Source-rule sampling | Sorted file list |
| Random seed | `42` |
| Generated dataset | 125 pairs from 20 sampled SigmaHQ rules |
| LLM interface | Anthropic Messages API |
| Model | `claude-sonnet-4-5` |
| Maximum output | `600` tokens |
| Temperature | Default |
| Saved results | `results/` |

The dataset version is also recorded in `DATASET_VERSION.md`.

---

## Scope and Limitations

GateKeeper is a research prototype rather than a production-ready detection engineering platform.

The reported results are based on the two evaluation datasets included in this repository and should therefore be interpreted as proof-of-concept findings.

The dissertation provides the full methodology, evaluation discussion, limitations, and future work.

---

## Author

**Chukwuebuka Cletus Eze**  
MSc Cyber Security  
University of the West of England (UWE), Bristol
