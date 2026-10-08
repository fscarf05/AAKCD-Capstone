from agents.delivery.delivery_agent import DeliveryAgent


def test_malicious_executable():
    agent = DeliveryAgent()

    event = {
        "source_ip": "192.168.1.50",
        "attachment": "invoice.exe"
    }

    alerts = agent.analyse_event(event)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].stage == "delivery"


def test_safe_pdf():
    agent = DeliveryAgent()

    event = {
        "source_ip": "192.168.1.60",
        "attachment": "report.pdf"
    }

    alerts = agent.analyse_event(event)

    assert len(alerts) == 0


def test_macro_document():
    agent = DeliveryAgent()

    event = {
        "source_ip": "10.0.0.25",
        "attachment": "payroll.xlsm"
    }

    alerts = agent.analyse_event(event)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert "Macro-enabled document" in alerts[0].description


def test_double_extension():
    agent = DeliveryAgent()

    event = {
        "source_ip": "192.168.1.70",
        "attachment": "invoice.pdf.exe"
    }

    alerts = agent.analyse_event(event)

    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert "disguised malicious attachment" in alerts[0].description


def test_phishing_email():
    agent = DeliveryAgent()

    event = {
        "source_ip": "172.16.0.15",
        "subject": "URGENT - Verify your account",
        "body": "Click here to verify your account."
    }

    alerts = agent.analyse_event(event)

    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].mitre_technique_id == "T1566"


def test_suspicious_url():
    agent = DeliveryAgent()

    event = {
        "source_ip": "192.168.20.12",
        "url": "http://example.com/reset-password"
    }

    alerts = agent.analyse_event(event)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].mitre_technique_id == "T1566.002"


def test_combined_attack():
    agent = DeliveryAgent()

    event = {
        "source_ip": "10.10.10.50",
        "attachment": "security_update.exe",
        "subject": "URGENT - Verify your account",
        "body": "Click here to verify your account.",
        "url": "http://example.com/secure-account/login"
    }

    alerts = agent.analyse_event(event)

    assert len(alerts) == 3
