"""Display projections for the public bundle formats. Trust comes from the CLI."""

import json
import re
from collections import Counter


CHECKS = ('Trusted keys', 'Decision journal', 'Control journal', 'Checkpoints', 'Chain and heads', 'Rekor anchors', 'Receipts')
V2_CHECKS = ('Trusted keys', 'Format and manifest', 'Decision and control journals', 'Artifacts and bindings',
             'Checkpoints and heads', 'Anchors and supplied receipts', 'Seal and accounting')
SECTIONS = {'1': 0, '4.1': 0, '2': 1, '3': 2, '4.2': 3, '4.3': 3, '4.4': 3, '4.5': 4, '4.6': 4, '6': 5, '5': 6}
ABSOLUTE_PATH = re.compile(r'(?<!\w)/(?:[A-Za-z0-9_.-]+/)+[^\s,\"]*')
CONTROL_FIELDS = ('trigger', 'restriction_persisted', 'outcome', 'event', 'kill', 'elapsed_ms', 'log_index', 'count',
                  'reason', 'operator_uid', 'applied', 'refusal', 'epoch_before', 'epoch_after', 'sequence', 'statement_sha256',
                  'execution_id', 'epoch', 'registry_checked', 'registry_released', 'scope_end', 'artifact_count', 'total_bytes',
                  'manifest_sha256', 'action', 'model_use_sequence', 'restriction_decision_id', 'window_start_ms',
                  'first_sequence', 'window_end_ms', 'complete', 'security_event_sequence', 'status', 'request_bytes', 'response_bytes')


def clean(value):
    if type(value) is int and abs(value) > 2**53 - 1:
        return str(value)
    if isinstance(value, str):
        return ABSOLUTE_PATH.sub('[redacted path]', value)
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value


def decode(data):
    return json.loads(data)


def jsonl(path):
    return [decode(line) for line in path.read_bytes().splitlines()]


def interpret(stdout, code, *, anchors, receipts, version):
    lines = stdout.splitlines()
    valid = code == 0 and 'RESULT: VALID' in lines and f'format: v{version}' in lines
    failure = next((line for line in lines if line.startswith('RESULT: INVALID, ')), None)
    stage = next((line for line in lines if line.startswith('STAGE: ')), None)
    verdict = 'VALID' if valid else 'INVALID' if code == 1 and failure and stage else 'UNKNOWN'
    result = {'verdict': verdict, 'stdout': stdout, 'exit_code': code, 'failure': failure,
              'message': failure, 'stage': stage, 'checks': [], 'version': version}
    for line in lines:
        match = re.fullmatch(r'gateway key: ([0-9a-f]{64}) \(trusted\)', line)
        if match:
            result['trusted_key'] = match[1]
        if line.startswith('log key: '):
            result['log_key'] = line.removeprefix('log key: ')
        summary = re.fullmatch(r'decision records (\d+), control records (\d+), checkpoints (\d+), anchors (\d+), receipts checked (\d+), trips (\d+), sealed (yes|no)', line)
        if summary:
            names = ('decisions', 'controls', 'checkpoints', 'anchors', 'receipts', 'trips', 'sealed')
            result['summary'] = dict(zip(names, [*(int(n) for n in summary.groups()[:6]), summary[7] == 'yes']))
    if version == 1:
        section = re.match(r'RESULT: INVALID, §([\d.]+):', failure or '')
        failed = SECTIONS.get(section[1]) if section else None
        for index, name in enumerate(CHECKS):
            status = 'UNKNOWN'
            if valid or (failed is not None and index < failed):
                status = 'passed'
                if index == 5 and not anchors:
                    status = 'not applicable'
                if index == 6 and not receipts:
                    status = 'not supplied'
            elif failed is not None:
                status = 'failed' if index == failed else 'not reached'
            result['checks'].append({'name': name, 'status': status})
    else:
        match = re.match(r'STAGE: ([1-7]);', stage or '')
        failed = int(match[1]) if match else None
        for index, name in enumerate(V2_CHECKS, 1):
            status = 'UNKNOWN'
            if valid or (failed is not None and index < failed):
                status = 'passed'
            elif failed is not None:
                status = 'failed' if index == failed else 'not reached'
            result['checks'].append({'name': name, 'status': status})
    return result


def display_entry(value, source):
    body = value['body']
    result = {key: body[key] for key in ('sequence', 'previous_sha256')}
    if source == 'decision':
        payload = body['payload']
        keys = ('event', 'outcome', 'reason', 'state', 'tick', 'epoch', 'policy_version', 'policy_sha256', 'subject')
        result['payload'] = {key: payload[key] for key in keys if key in payload}
        result['decision_id'] = body.get('decision_id')
        if payload.get('recovery'):
            result['payload']['recovery'] = {'reason_sha256': payload['recovery'].get('reason_sha256')}
    else:
        entry = body['entry']
        result['entry'] = {'kind': entry['kind'], **{key: entry[key] for key in CONTROL_FIELDS if key in entry}}
        marker = entry.get('marker_id')
        if isinstance(marker, str) and re.fullmatch(r'tw-(0[1-9]|1[0-6])', marker):
            result['entry']['marker_id'] = marker
        if entry['kind'] == 'reset' and result['entry'].get('reason') is not None:
            result['entry']['reason'] = '[redacted operator text]'
    return {'body': result, 'sha256': value['sha256']}


def journal_rows(records, checkpoints, source):
    rows = []
    for record in records:
        body = record['body']
        value = body['payload'] if source == 'decision' else body['entry']
        checkpoint = next((cp for cp in checkpoints if cp['statement'][source]['sequence'] >= body['sequence']), None)
        wall = checkpoint['statement']['wall_time_unix_ms'] if checkpoint else None
        rows.append({'source': source, 'sequence': body['sequence'], 'hash': record['sha256'], 'previous': body['previous_sha256'],
                     'label': 'AS STORED', 'wall_ms': wall, 'wall_source': 'APPROX · checkpoint' if wall is not None else None,
                     'event': value.get('event') if source == 'decision' else value['kind'],
                     'outcome': 'trip' if value.get('kind') == 'tripped' else value.get('outcome'),
                     'reason': value.get('trigger') or value.get('reason'), 'state': value.get('state'),
                     'tick': value.get('tick'), 'epoch': value.get('epoch'), 'raw': record})
    return rows


def read_bundle(directory, label, name, trusted_key, receipt_lines, receipt_keys):
    controls = [display_entry(value, 'control') for value in jsonl(directory / 'control.jsonl')[1:]]
    decisions = [display_entry(value, 'decision') for value in jsonl(directory / 'decision.jsonl')[1:]]
    checkpoints = []
    for value in jsonl(directory / 'checkpoints.jsonl'):
        statement = value['statement']
        checkpoints.append({'statement': statement, 'hash': value['statement_sha256'],
                            'receipt': (statement['sequence'], value['statement_sha256']) in receipt_keys,
                            'slh_bytes': len(value.get('slh_dsa_sha2_128f', '')) // 2,
                            'ecdsa_bytes': len(value.get('ecdsa_p256_sha256', '')) // 2})
    anchors = []
    if (directory / 'rekor-anchors.jsonl').exists():
        for item in jsonl(directory / 'rekor-anchors.jsonl'):
            anchors.append({'checkpoint_sequence': item['checkpoint_sequence'], 'uuid': item['uuid'],
                            'statement_sha256': item['statement_sha256'], 'logIndex': item['entry']['logIndex'],
                            'integratedTime': item['entry']['integratedTime']})
    d, c = journal_rows(decisions, checkpoints, 'decision'), journal_rows(controls, checkpoints, 'control')
    last = decisions[-1]['body']['payload'] if decisions else {}
    overview = {'run': name, 'project': None, 'phase': 'recorded', 'process': 'not applicable: recorded evidence',
                'state': last.get('state'), 'epoch': last.get('epoch'), 'state_source': 'last recorded decision', 'read_age': 0,
                'healthy_read': False, 'errors': {}, 'reset_reasons': [], 'policy_version': last.get('policy_version'),
                'policy_sha256': last.get('policy_sha256'), 'subject': last.get('subject'), 'checkpoint_count': len(checkpoints),
                'last_checkpoint': checkpoints[-1]['statement'] if checkpoints else None,
                'receipt_lines': receipt_lines, 'receipt_checkpoints': len(receipt_keys),
                'anchors': dict(Counter(row['outcome'] for row in c if row['event'] == 'anchor')),
                'alarms': dict(Counter(row['outcome'] for row in c if row['event'] == 'alarm'))}
    trips = {}
    for index, row in enumerate(c):
        if row['event'] != 'tripped':
            continue
        tail = c[index + 1:]
        cutoff = next((n for n, later in enumerate(tail) if later['event'] in ('tripped', 'reset')), len(tail))
        effects = [item for item in tail[:cutoff] if item['event'] in ('kill', 'daemon_lost', 'alarm', 'anchor')]
        checkpoint = next((cp for cp in checkpoints if cp['statement']['reason'] == 'tripped' and cp['statement']['control']['sequence'] >= row['sequence']), None)
        event_sequence = row['raw']['body']['entry'].get('security_event_sequence')
        leading = [item for item in c[:index] if event_sequence is not None and item['sequence'] == event_sequence]
        if not leading:
            leading = [item for item in d if item['outcome'] == 'DENY' and item['reason'] == 'QUOTA_EXHAUSTED'][-1:]
        event = leading[0]['raw']['body'].get('entry', {}) if leading else {}
        decision_id = event.get('restriction_decision_id')
        risk = next((item for item in d if decision_id and item['raw']['body'].get('decision_id') == decision_id), None)
        resets = [{'row': item, 'recovery': next((decision for decision in d if decision['event'] == 'Recovery' and decision['epoch'] == item['raw']['body']['entry'].get('epoch_after')), None)}
                  for item in tail[cutoff:cutoff + 1] if item['event'] == 'reset']
        trips[str(row['sequence'])] = {'trip': row, 'risk': risk, 'leading': leading, 'effects': effects, 'resets': resets,
                                       'checkpoint': checkpoint, 'errors': {}}
    profile = decode((directory / 'bundle.json').read_bytes()) if (directory / 'bundle.json').exists() else None
    names = ('bundle.json', 'artifacts.json', 'decision.jsonl', 'control.jsonl', 'checkpoints.jsonl', 'gateway-keys.pub.json', 'rekor-anchors.jsonl', 'rekor-log.pub.pem')
    evidence = {'bundles': [{'name': name, 'files': {file: 'present' for file in names if (directory / file).exists()}}],
                'errors': {}, 'key_id': trusted_key['gateway_key_id'], 'receipt_lines': receipt_lines, 'decision': decisions,
                'control': controls, 'checkpoint': checkpoints, 'anchors': anchors, 'profile': profile}
    return clean({'label': label, 'overview': overview, 'evidence': evidence, 'trips': trips, 'decision': d, 'control': c})
