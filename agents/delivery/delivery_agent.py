from pathlib import Path
import os
import re

from agents.delivery.alerts import make_alert
from agents.delivery.ollama_analysis import OllamaAnalysis


class DeliveryAgent:
    """
    AAKCD Delivery Agent

    Detects suspicious activity associated with the Delivery stage
    of the Cyber Kill Chain.

    The agent can analyse:
    - Suspicious file attachments
    - Double-extension / disguised files
    - Macro-enabled Office documents
    - Phishing emails and messages
    - Suspicious URLs
    - Real files stored on disk
    - Entire folders of files
    """

    # ---------------------------------------------------------
    # Suspicious file extensions
    # ---------------------------------------------------------

    SUSPICIOUS_EXTENSIONS = [
        ".exe",
        ".js",
        ".bat",
        ".cmd",
        ".scr",
        ".ps1",
        ".vbs",
        ".jar",
        ".msi",
        ".zip",
    ]

    # ---------------------------------------------------------
    # Macro-enabled Office extensions
    # ---------------------------------------------------------

    MACRO_EXTENSIONS = [
        ".docm",
        ".xlsm",
        ".pptm",
    ]

    # ---------------------------------------------------------
    # Common harmless extensions used before a malicious
    # second extension, e.g. invoice.pdf.exe
    # ---------------------------------------------------------

    DISGUISED_EXTENSIONS = [
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".jpg",
        ".jpeg",
        ".png",
    ]

    # ---------------------------------------------------------
    # Phishing keywords
    # ---------------------------------------------------------

    PHISHING_KEYWORDS = [
        "urgent",
        "verify your account",
        "password expired",
        "reset your password",
        "click here",
        "account suspended",
        "payment required",
        "invoice attached",
        "confirm your identity",
    ]

    # ---------------------------------------------------------
    # Suspicious URL keywords
    # ---------------------------------------------------------

    SUSPICIOUS_URL_KEYWORDS = [
        "login",
        "verify",
        "secure-account",
        "reset-password",
        "confirm-account",
    ]

    # =========================================================
    # MAIN EVENT ANALYSIS
    # =========================================================

    def __init__(self, ai_enabled=None):
        if ai_enabled is None:
            ai_enabled = os.getenv("DELIVERY_AI_ENABLED", "").lower() in {
                "1", "true", "yes"
            }
        self.ai_analysis = OllamaAnalysis() if ai_enabled else None

    def analyse_event(self, event):
        """Preserve rule decisions and enrich them using optional local analysis."""
        alerts = self._analyse_rules(event)
        if self.ai_analysis is not None:
            ai_alert = self.ai_analysis.analyse(event)
            analysis = self.ai_analysis
            for alert in alerts:
                alert.ai_status = "ok" if analysis.last_status == "completed" else "unavailable"
                if analysis.last_finding is not None:
                    alert.ai_summary = analysis.last_finding["reason"]
                elif analysis.last_error:
                    alert.evidence["ai_error"] = analysis.last_error
            if ai_alert is not None:
                alerts.append(ai_alert)
        return alerts

    def _analyse_rules(self, event):
        """
        Analyse an event supplied to the Delivery Agent.

        Returns:
            list[Alert]
        """

        alerts = []

        # -----------------------------------------------------
        # Extract event information
        # -----------------------------------------------------

        attachment = str(
            event.get("attachment")
            or event.get("filename")
            or event.get("file_name")
            or event.get("attachment_name")
            or ""
        ).lower()

        subject = str(
            event.get("subject")
            or ""
        ).lower()

        body = str(
            event.get("body")
            or event.get("message")
            or event.get("email_body")
            or event.get("text")
            or ""
        ).lower()

        # Combine subject and body for phishing detection
        message = f"{subject} {body}"

        url = str(
            event.get("url")
            or ""
        ).lower()


        # =====================================================
        # 1. DOUBLE-EXTENSION / DISGUISED FILE
        #
        # Example:
        # invoice.pdf.exe
        # =====================================================

        if attachment:

            suffixes = [
                suffix.lower()
                for suffix in Path(attachment).suffixes
            ]

            if len(suffixes) >= 2:

                second_last_extension = suffixes[-2]
                final_extension = suffixes[-1]

                if (
                    second_last_extension in self.DISGUISED_EXTENSIONS
                    and final_extension in self.SUSPICIOUS_EXTENSIONS
                ):

                    alerts.append(
                        make_alert(
                            severity="CRITICAL",
                            description=(
                                "Possible disguised malicious attachment detected: "
                                f"{attachment}"
                            ),
                            technique="T1566.001",
                            confidence="high",
                            evidence={
                                "detector": "disguised_attachment",
                                "filename": attachment,
                                "extensions": suffixes,
                            },
                            event=event,
                        )
                    )

                    # Prevent the same file also being reported
                    # as a normal executable.
                    return alerts

        # =====================================================
        # 2. SUSPICIOUS ATTACHMENT
        # =====================================================

        for extension in self.SUSPICIOUS_EXTENSIONS:

            if attachment.endswith(extension):

                alerts.append(
                    make_alert(
                        severity="HIGH",
                        description=(
                            "Suspicious attachment detected: "
                            f"{attachment}"
                        ),
                        technique="T1566.001",
                        confidence="high",
                        evidence={
                            "detector": "suspicious_attachment",
                            "filename": attachment,
                            "extension": extension,
                        },
                        event=event,
                    )
                )

                break

        # =====================================================
        # 3. MACRO-ENABLED OFFICE DOCUMENT
        # =====================================================

        for extension in self.MACRO_EXTENSIONS:

            if attachment.endswith(extension):

                alerts.append(
                    make_alert(
                        severity="HIGH",
                        description=(
                            "Macro-enabled document detected: "
                            f"{attachment}"
                        ),
                        technique="T1566.001",
                        confidence="high",
                        evidence={
                            "detector": "macro_document",
                            "filename": attachment,
                            "extension": extension,
                        },
                        event=event,
                    )
                )

                break

        # =====================================================
        # 4. PHISHING EMAIL / MESSAGE
        # =====================================================

        detected_keywords = []

        for keyword in self.PHISHING_KEYWORDS:

            if keyword in message:
                detected_keywords.append(keyword)

        if detected_keywords:

            alerts.append(
                make_alert(
                    severity="MEDIUM",
                    description=(
                        "Possible phishing message detected. Indicators: "
                        + ", ".join(detected_keywords)
                    ),
                    technique="T1566",
                    confidence="medium",
                    evidence={
                        "detector": "phishing_keywords",
                        "matched_keywords": detected_keywords,
                    },
                    event=event,
                )
            )

        # =====================================================
        # 5. SUSPICIOUS URL
        # =====================================================

        for keyword in self.SUSPICIOUS_URL_KEYWORDS:

            if keyword in url:

                alerts.append(
                    make_alert(
                        severity="HIGH",
                        description=(
                            f"Suspicious URL detected: {url}"
                        ),
                        technique="T1566.002",
                        confidence="high",
                        evidence={
                            "detector": "url_keyword",
                            "url": url,
                            "matched_keyword": keyword,
                        },
                        event=event,
                    )
                )

                break

        return alerts

    # =========================================================
    # COMPATIBILITY METHODS
    # =========================================================

    def analyze_event(self, event):
        """
        American spelling version.
        """

        return self.analyse_event(event)

    def analyze(self, event):
        """
        Used by older main.py code.

        Returns the first alert if one is detected,
        otherwise returns None.
        """

        alerts = self.analyse_event(event)

        if alerts:
            return alerts[0]

        return None

    # =========================================================
    # REAL FILE ANALYSIS
    # =========================================================

    def analyse_file(self, file_path):
        """
        Analyse a real file stored on disk.

        The file is NOT executed.

        Every file is checked by filename.

        Text-based files are also read so the Delivery Agent
        can search their contents for phishing language and URLs.
        """

        path = Path(file_path)

        # -----------------------------------------------------
        # File does not exist
        # -----------------------------------------------------

        if not path.exists():

            print(
                f"File not found: {file_path}"
            )

            return []

        # -----------------------------------------------------
        # Path is not a file
        # -----------------------------------------------------

        if not path.is_file():

            print(
                f"Not a file: {file_path}"
            )

            return []

        # -----------------------------------------------------
        # Create an event from the real file
        # -----------------------------------------------------

        event = {
            "source_file": str(path.resolve()),
            "attachment": path.name,
        }

        # -----------------------------------------------------
        # File types that can be safely read as text
        # -----------------------------------------------------

        text_extensions = {
            ".txt",
            ".log",
            ".csv",
            ".json",
            ".md",
            ".html",
            ".htm",
            ".eml",
        }

        # -----------------------------------------------------
        # Read text content
        # -----------------------------------------------------

        if path.suffix.lower() in text_extensions:

            try:

                content = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )

                event["message"] = content

                # ---------------------------------------------
                # Find URLs inside the file
                # ---------------------------------------------

                urls = re.findall(
                    r"https?://[^\s<>\"']+",
                    content,
                )

                if urls:
                    event["url"] = urls[0]

            except Exception as error:

                print(
                    f"Could not read {path.name}: {error}"
                )

        # Run the real file through the same detection engine
        return self.analyse_event(event)

    # ---------------------------------------------------------
    # American spelling compatibility
    # ---------------------------------------------------------

    def analyze_file(self, file_path):

        return self.analyse_file(file_path)

    # =========================================================
    # DIRECTORY SCANNER
    # =========================================================

    def scan_directory(self, directory):
        """
        Scan all files directly inside a directory.

        Returns:
            list[Alert]
        """

        directory_path = Path(directory)

        # -----------------------------------------------------
        # Directory does not exist
        # -----------------------------------------------------

        if not directory_path.exists():

            print(
                f"Directory not found: {directory}"
            )

            return []

        # -----------------------------------------------------
        # Provided path is not a directory
        # -----------------------------------------------------

        if not directory_path.is_dir():

            print(
                f"Not a directory: {directory}"
            )

            return []

        all_alerts = []

        # -----------------------------------------------------
        # Header
        # -----------------------------------------------------

        print()
        print("=" * 55)
        print("AAKCD DELIVERY AGENT - DIRECTORY SCAN")
        print("=" * 55)

        print(
            f"Scanning directory: {directory_path}"
        )

        print("-" * 55)

        # -----------------------------------------------------
        # Scan files
        # -----------------------------------------------------

        for file_path in sorted(
            directory_path.iterdir()
        ):

            if not file_path.is_file():
                continue

            print()
            print(
                f"Scanning: {file_path.name}"
            )

            alerts = self.analyse_file(
                file_path
            )

            # -------------------------------------------------
            # Alert detected
            # -------------------------------------------------

            if alerts:

                for alert in alerts:

                    print(
                        "ALERT DETECTED"
                    )

                    print(
                        alert.to_dict()
                    )

                all_alerts.extend(
                    alerts
                )

            # -------------------------------------------------
            # No alert detected
            # -------------------------------------------------

            else:

                print(
                    "No suspicious delivery activity detected."
                )

        # -----------------------------------------------------
        # Scan summary
        # -----------------------------------------------------

        print()
        print("-" * 55)

        print(
            "Directory scan complete."
        )

        print(
            f"Total alerts detected: {len(all_alerts)}"
        )

        print("=" * 55)

        return all_alerts
