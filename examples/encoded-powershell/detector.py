"""Observe PowerShell encoded-command flags in normalized process telemetry."""


def detect(event):
    event_type = str(event.get("event_type", "")).lower()
    process = str(event.get("process_name", "")).lower()
    if event_type != "process.creation":
        return None
    if process not in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        return None
    command = str(event.get("cmdline", "")).lower()
    if " -encodedcommand " in command or " -enc " in command or " -e " in command:
        return {
            "rule_id": "divalia.encoded-powershell",
            "severity": "medium",
            "confidence": 60,
            "message": "PowerShell encoded-command flag observed; review the parent, user and script provenance.",
        }
    return None
