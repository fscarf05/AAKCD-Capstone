from shared.alert_schema import Alert


class DeliveryAgent:
    def analyse_event(self, event):
        attachment = event.get("attachment", "").lower()
        source_ip = event.get("source_ip")

        suspicious_extensions = [
            ".exe",
            ".js",
            ".bat",
            ".scr",
            ".zip"
        ]

        for extension in suspicious_extensions:
            if attachment.endswith(extension):
                return Alert(
                    agent="Delivery Agent",
                    severity="high",
                    activity=f"Suspicious attachment detected: {attachment}",
                    kill_chain_stage="Delivery",
                    mitre_technique="T1566 - Phishing",
                    confidence=0.85,
                    source_ip=source_ip
                )

        return None