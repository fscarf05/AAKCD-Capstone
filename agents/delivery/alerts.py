"""Delivery-specific construction of the team's shared alerts."""
from ipaddress import ip_address

from shared.alert_schema import Alert


TECHNIQUES = {
    'T1566': 'Phishing',
    'T1566.001': 'Spearphishing Attachment',
    'T1566.002': 'Spearphishing Link',
}
ACTIONS = {
    'T1566': ['Verify the sender through a trusted channel.',
              'Do not supply credentials or payment until the request is verified.'],
    'T1566.001': ['Do not open or execute the attachment.',
                  'Refer the attachment to the security analyst for isolated analysis.'],
    'T1566.002': ['Do not follow the link or submit credentials.',
                  'Verify the destination and sender through a trusted channel.'],
}


def source_ip(value):
    """Never use a filename, placeholder or inferred address as a correlation key."""
    try:
        return str(ip_address(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def make_alert(*, severity, description, technique, confidence, event, evidence):
    evidence = dict(evidence)
    for key in ('source_file', 'scenario_id', 'simulation'):
        if key in event:
            evidence[key] = event[key]
    return Alert(
        agent='delivery', stage='delivery', severity=severity,
        confidence=confidence, description=description,
        mitre_technique_id=technique, mitre_technique=TECHNIQUES[technique],
        source_ip=source_ip(event.get('source_ip')),
        evidence=evidence, recommended_actions=list(ACTIONS[technique]),
    )
