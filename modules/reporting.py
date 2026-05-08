import json

def save_report(data, filename="reports/report.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)