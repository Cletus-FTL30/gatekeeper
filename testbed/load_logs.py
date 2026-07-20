import urllib.request
import json

ES = "http://localhost:9200"
INDEX = "logs"

# Realistic log events: each has a CommandLine field (like Windows process logs)
log_events = [
    {"CommandLine": "cmd.exe whoami"},
    {"CommandLine": "powershell.exe whoami"},
    {"CommandLine": "wmic.exe whoami"},
    {"CommandLine": "pwsh.exe whoami"},
    {"CommandLine": "cmd.exe dir"},
    {"CommandLine": "notepad.exe file.txt"},
    {"CommandLine": "powershell.exe Get-Process"},
    {"CommandLine": "explorer.exe"},
]

# First, delete the index if it exists (clean start)
try:
    req = urllib.request.Request(f"{ES}/{INDEX}", method="DELETE")
    urllib.request.urlopen(req)
    print("Cleared old index.")
except Exception:
    print("No old index to clear (fine).")

# Add each event to the index
for i, event in enumerate(log_events):
    data = json.dumps(event).encode()
    req = urllib.request.Request(
        f"{ES}/{INDEX}/_doc/{i}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    urllib.request.urlopen(req)
    print(f"Loaded: {event['CommandLine']}")

# Refresh so the documents are searchable immediately
req = urllib.request.Request(f"{ES}/{INDEX}/_refresh", method="POST")
urllib.request.urlopen(req)
print("\nAll log events loaded into Elasticsearch.")
