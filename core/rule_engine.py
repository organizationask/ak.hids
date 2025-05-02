def apply_rules(log_file, alert_file):
    """Apply rules to detect suspicious activity and generate alerts."""
    with open(log_file, "r") as logs, open(alert_file, "a") as alerts:
        for line in logs:
            if "suspicious" in line.lower():  # Example rule
                alert_message = f"ALERT: {line.strip()}"
                alerts.write(alert_message + "\n")