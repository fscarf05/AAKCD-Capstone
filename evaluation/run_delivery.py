"""Run from the repository root: python3 -m evaluation.run_delivery."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
from time import perf_counter

from agents.delivery.delivery_agent import DeliveryAgent
from agents.delivery.ollama_analysis import MODEL

DEFAULT_DATASET = Path(__file__).with_name('delivery_cases.json')


def load_cases(path):
    cases = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(cases, list) or not cases:
        raise ValueError('Dataset must be a nonempty list')
    seen = set()
    fields = {'attachment', 'filename', 'file_name', 'attachment_name', 'subject',
              'body', 'message', 'email_body', 'text', 'url'}
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError('Each case must be an object')
        if not isinstance(case.get('id'), str) or not case['id'] or case['id'] in seen:
            raise ValueError('Case IDs must be nonempty and unique')
        seen.add(case['id'])
        if type(case.get('suspicious')) is not bool:
            raise ValueError('Labels must be booleans')
        for key in ('category', 'rationale'):
            if not isinstance(case.get(key), str) or not case[key].strip():
                raise ValueError('Each case needs a category and label rationale')
        event = case.get('event')
        if not isinstance(event, dict) or not event or not set(event) <= fields:
            raise ValueError('Events must contain only supported input fields')
        if not all(isinstance(v, str) for v in event.values()) or not any(event.values()):
            raise ValueError('Event values must be strings with some nonempty input')
    return cases


def metrics(rows):
    counts = Counter(row['outcome'] for row in rows)
    tp, fp, tn, fn = (counts[key] for key in ('TP', 'FP', 'TN', 'FN'))
    def ratio(a, b):
        return a / b if b else None
    elapsed = sorted(row['elapsed_seconds'] for row in rows)
    return {
        'cases': len(rows), 'true_positives': tp, 'false_positives': fp,
        'true_negatives': tn, 'false_negatives': fn,
        'precision': ratio(tp, tp + fp), 'recall': ratio(tp, tp + fn),
        'f1': ratio(2 * tp, 2 * tp + fp + fn),
        'false_positive_rate': ratio(fp, fp + tn),
        'accuracy': ratio(tp + tn, len(rows)),
        'total_seconds': sum(elapsed),
        'mean_seconds': ratio(sum(elapsed), len(rows)),
        'p95_seconds': elapsed[max(0, (95 * len(elapsed) + 99) // 100 - 1)] if elapsed else None,
    }


def evaluate(cases, include_ai=False, agent_factory=DeliveryAgent):
    runs = {}
    for mode in (['rules', 'rules_plus_ai'] if include_ai else ['rules']):
        agent = agent_factory(ai_enabled=mode == 'rules_plus_ai')
        rows = []
        for case in cases:
            start = perf_counter()
            alerts = agent.analyse_event(dict(case['event']))
            elapsed = perf_counter() - start
            status = agent.ai_analysis.last_status if agent.ai_analysis else 'disabled'
            detected = bool(alerts)
            outcome = ('TP' if detected else 'FN') if case['suspicious'] else ('FP' if detected else 'TN')
            rows.append({
                'id': case['id'], 'category': case['category'],
                'expected_suspicious': case['suspicious'], 'detected': detected,
                'outcome': outcome, 'ai_status': status, 'elapsed_seconds': elapsed,
                'ai_error': agent.ai_analysis.last_error if agent.ai_analysis else None,
                'ai_finding': agent.ai_analysis.last_finding if agent.ai_analysis else None,
                'alerts': [alert.to_dict() for alert in alerts],
            })
        runs[mode] = {
            'metrics': metrics(rows),
            'ai_status_counts': dict(Counter(row['ai_status'] for row in rows)),
            'by_category': {category: metrics([r for r in rows if r['category'] == category])
                            for category in sorted({r['category'] for r in rows})},
            'cases': rows,
        }
    complete = include_ai and all(r['ai_status'] == 'completed' for r in runs['rules_plus_ai']['cases'])
    comparison = {'valid_full_ai_comparison': bool(complete)}
    if include_ai:
        baseline = {r['id']: r for r in runs['rules']['cases']}
        changed = [r for r in runs['rules_plus_ai']['cases'] if r['detected'] != baseline[r['id']]['detected']]
        comparison['changed_predictions'] = [r['id'] for r in changed]
        comparison['additional_true_positives'] = [r['id'] for r in changed if r['outcome'] == 'TP']
        comparison['additional_false_positives'] = [r['id'] for r in changed if r['outcome'] == 'FP']
    return {'runs': runs, 'comparison': comparison}


def markdown_report(report):
    lines = ['# Delivery Agent evaluation', '',
             'Synthetic development cases; results do not establish real-world accuracy.', '',
             f"Dataset SHA-256: `{report['dataset_sha256']}`", '',
             '| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Mean seconds |',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    def number(value):
        return 'N/A' if value is None else f'{value:.3f}'
    for mode, run in report['runs'].items():
        m = run['metrics']
        values = [mode] + [str(m[k]) for k in ('true_positives', 'false_positives', 'true_negatives', 'false_negatives')]
        values += [number(m[k]) for k in ('precision', 'recall', 'f1', 'mean_seconds')]
        lines.append('| ' + ' | '.join(values) + ' |')
    lines += ['', 'Full AI comparison valid: ' + str(report['comparison']['valid_full_ai_comparison']),
              'If false, AI was not requested or at least one case used fallback. Do not claim AI improvement from an incomplete run.', '']
    for mode, run in report['runs'].items():
        lines += [f'## {mode}', '', f"AI status: {run['ai_status_counts']}", '']
        for row in run['cases']:
            if row['ai_status'] == 'failed':
                lines.append(f"- AI failure {row['id']}: {row['ai_error']}")
        errors = [r for r in run['cases'] if r['outcome'] in ('FP', 'FN')]
        lines += [f"- {r['id']}: {r['outcome']} ({r['category']})" for r in errors] or ['No classification errors.']
        lines.append('')
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-ai', action='store_true', help='Also call local Ollama on every case')
    parser.add_argument('--dataset', type=Path, default=DEFAULT_DATASET)
    parser.add_argument('--output-dir', type=Path, default=Path('outputs/delivery_evaluation'))
    args = parser.parse_args(argv)
    cases = load_cases(args.dataset)
    report = evaluate(cases, args.with_ai)
    report.update({
        'created_at': datetime.now(timezone.utc).isoformat(),
        'dataset_sha256': hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        'python_version': platform.python_version(), 'platform': platform.platform(),
        'model_requested': MODEL if args.with_ai else None,
        'dataset_type': 'synthetic development set',
        'timing_note': 'Sequential event latency, including cold start if present; excludes setup and report writing.',
    })
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / 'results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    summary = markdown_report(report)
    (args.output_dir / 'summary.md').write_text(summary, encoding='utf-8')
    print(summary)
    print(f'Reports saved to {args.output_dir}')
    return 2 if args.with_ai and not report['comparison']['valid_full_ai_comparison'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
