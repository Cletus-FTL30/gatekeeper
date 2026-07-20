import urllib.request
import json

ES = "http://localhost:9200"
INDEX = "logs"

# Match patterns based on the official Sigma conversion of each rule:
#   Original rule matches CommandLine containing ".exe whoami"
#   Weakened rule matches CommandLine containing "cmd.exe whoami"
# We express these as Elasticsearch wildcard queries (confirmed working format).
original_pattern = "*.exe whoami*"
weakened_pattern = "*cmd.exe whoami*"

def run_query(pattern):
    """Run a wildcard query against the SIEM and return the matching command lines."""
    body = json.dumps({
        "query": {
            "wildcard": {
                "CommandLine.keyword": pattern
            }
        }
    }).encode()
    req = urllib.request.Request(
        f"{ES}/{INDEX}/_search",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    result = json.loads(urllib.request.urlopen(req).read().decode())
    hits = result["hits"]["hits"]
    return [h["_source"]["CommandLine"] for h in hits]

print("Running the ORIGINAL rule against the SIEM...")
original_hits = run_query(original_pattern)
for h in original_hits:
    print("   caught:", h)

print("\nRunning the WEAKENED rule against the SIEM...")
weakened_hits = run_query(weakened_pattern)
for h in weakened_hits:
    print("   caught:", h)

missed = set(original_hits) - set(weakened_hits)
print("\n" + "=" * 50)
print(f"Original rule caught: {len(original_hits)} events")
print(f"Weakened rule caught: {len(weakened_hits)} events")
print(f"COVERAGE DELTA: {len(missed)} events missed by the weakened rule")
for m in missed:
    print("   MISSED:", m)
