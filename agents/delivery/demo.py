"""Generate only the Delivery stage of a safe, simulated attack chain."""
import argparse
from ipaddress import ip_address
from pathlib import Path

from agents.delivery.delivery_agent import DeliveryAgent
from agents.delivery.jsonl_output import append_alerts, DEFAULT_LOG


DEMO_FILE = Path(__file__).resolve().parents[2] / 'wazuh/delivery/demo_files/invoice.pdf.exe'


def demo_event(attacker_ip, scenario_id, file_path=DEMO_FILE):
    return {
        'source_ip': str(ip_address(attacker_ip)),
        'scenario_id': scenario_id,
        'simulation': True,
        'attachment': Path(file_path).name,
        'file_path': str(Path(file_path).expanduser().resolve()),
        'subject': 'Invoice for review',
        'body': 'Open the unsolicited attachment to view the invoice.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-ip', required=True, type=ip_address,
                        help='Team-agreed simulated attacker IP; no network traffic is sent')
    parser.add_argument('--scenario-id', default='ransomware-demo-01')
    parser.add_argument('--output', default=DEFAULT_LOG)
    parser.add_argument('--with-ai', action='store_true')
    parser.add_argument('--file-path', type=Path, default=DEMO_FILE,
                        help='Path to a safe local demo attachment; it is never executed')
    args = parser.parse_args()
    agent = DeliveryAgent(ai_enabled=args.with_ai)
    alerts = agent.analyse_event(demo_event(str(args.source_ip), args.scenario_id, args.file_path))
    path = append_alerts(alerts, args.output)
    print(f'Appended {len(alerts)} simulated Delivery alert(s) to {path}')
    print('The default fixture is empty. No file was executed or network traffic sent.')


if __name__ == '__main__':
    main()
