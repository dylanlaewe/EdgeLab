"""Content-bound Data contracts. Validation is not scientific/operational approval."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

INITIAL_BASELINE = '4e99cfac90e0af601158c1528c70574dd5dafeda'
DATA_LOCATIONS = {
    'availability': 'data/availability/*.json', 'permission': 'data/permissions/*.json',
    'membership': 'data/membership/*.json', 'observation': 'data/normalized/*.json',
    'feature': 'data/features/*.json', 'manifest': 'data/derived/*.json',
}
IMMUTABLE_PREFIXES = ('reports/', 'docs/handoffs/', 'schemas/',
                      'research/', 'strategies/', 'data/')
COMPLETED_TIMES = {'created_at', 'occurred_at', 'issued_at', 'registered_at',
                   'protocol_frozen_at', 'started_at', 'completed_at', 'as_of',
                   'terms_checked_at', 'updated_at', 'observed_at', 'retrieved_at',
                   'publication_at', 'corrected_at', 'reviewed_at', 'available_at'}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def clock_checks(record: dict, now: datetime | None = None) -> None:
    from .validate import instant
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() is None:
        raise ValueError('Evaluation clock needs timezone')
    for field in COMPLETED_TIMES:
        if record.get(field) is not None and instant(record[field]) > now:
            raise ValueError(f'Future completed fact: {field}')


def safe_path(root: Path, path: str) -> Path:
    from .validate import reference
    if not isinstance(path, str) or Path(path).as_posix() != path or Path(path).is_absolute() or '..' in Path(path).parts:
        raise ValueError('Noncanonical reference')
    result = reference(root, path)
    if result.relative_to(root.resolve()).as_posix() != path:
        raise ValueError('Aliased reference')
    return result


def blob(root: Path, ref: dict) -> bytes:
    data = safe_path(root, ref['path']).read_bytes()
    if digest(data) != ref['sha256']:
        raise ValueError('Content digest mismatch: ' + ref['path'])
    if ref['media_type'] == 'application/json':
        from .validate import read
        read(safe_path(root, ref['path']))
    else:
        data.decode('utf-8')
    return data


def exact(root: Path, ref: dict, expected: set[str], *, now: datetime | None = None) -> dict:
    from .validate import LOCATIONS, read, validate_record
    kind = ref['kind']
    if kind not in expected:
        raise ValueError('Wrong reference type')
    locations = {**LOCATIONS, **DATA_LOCATIONS}
    path = safe_path(root, ref['path'])
    if kind not in locations or path not in root.resolve().glob(locations[kind]):
        raise ValueError('Reference outside typed registry')
    if digest(path.read_bytes()) != ref['sha256']:
        raise ValueError('Content digest mismatch: ' + ref['path'])
    record = read(path)
    if (record.get('id'), record.get('version')) != (ref['id'], ref['version']):
        raise ValueError('Reference identity mismatch')
    if path.name != f"{ref['id']}.v{ref['version']}.json":
        raise ValueError('Reference filename mismatch')
    if kind not in DATA_LOCATIONS:
        validate_record(kind, record, root, now=now)
    else:
        shape(root, kind, record)
    return record


def shape(root: Path, kind: str, record: dict) -> None:
    from .validate import CHECKER, read
    Draft202012Validator(read(root / f'schemas/{kind}.schema.json'), format_checker=CHECKER).validate(record)


def sample_keys(record: dict) -> frozenset[str]:
    """Namespaced event/outcome identity survives manifest/dataset renaming."""
    return frozenset(canonical(s).decode() for s in record['samples'])


def membership_digest(record: dict) -> str:
    return digest(canonical(sorted(sample_keys(record))))


def validate_data(root: Path, kind: str, record: dict, *, now: datetime | None = None,
                  stack: tuple[str, ...] = ()) -> None:
    from .validate import instant
    shape(root, kind, record)
    clock_checks(record, now)
    identity = f"{kind}:{record['id']}:{record['version']}"
    if identity in stack:
        raise ValueError('Dependency cycle')
    stack = (*stack, identity)

    def parent(ref: dict, types: set[str]) -> dict:
        r = exact(root, ref, types, now=now)
        if ref['kind'] in DATA_LOCATIONS:
            validate_data(root, ref['kind'], r, now=now, stack=stack)
        return r

    if record['supersedes']:
        old = parent(record['supersedes'], {kind})
        if old['id'] != record['id'] or old['version'] != record['version'] - 1:
            raise ValueError('Correction must name previous exact version')
        if instant(old['created_at']) > instant(record['created_at']):
            raise ValueError('Correction precedes original')
    elif record['version'] != 1:
        raise ValueError('Correction requires predecessor')
    for field in ('config', 'snapshot', 'quality_report'):
        if field in record and record[field]['media_type'] != 'application/json':
            raise ValueError('Wrong blob type: ' + field)
    for field in ('parser', 'normalizer', 'transform'):
        if field in record and record[field]['media_type'] != 'text/x-python':
            raise ValueError('Wrong code type: ' + field)
    for value in record.values():
        if isinstance(value, dict) and set(value) == {'path', 'sha256', 'media_type'}:
            blob(root, value)
    if kind == 'membership':
        if membership_digest(record) != record['membership_sha256']:
            raise ValueError('Membership digest mismatch')
    elif kind == 'permission':
        if instant(record['valid_until']) <= instant(record['reviewed_at']):
            raise ValueError('Invalid permission validity interval')
    elif kind == 'availability':
        parent(record['source_ref'], {'source'})
        if instant(record['available_at']) > instant(record['observed_at']):
            raise ValueError('Availability evidence observed before claimed availability')
        if record['basis'] == 'contemporaneous_capture' and record['available_at'] != record['observed_at']:
            raise ValueError('Capture cannot establish earlier availability')
    elif kind == 'observation':
        source = parent(record['source_ref'], {'source'})
        if source['url'] != record['source_url']:
            raise ValueError('Source URL mismatch')
        for field in ('publication_at', 'corrected_at'):
            if record[field] and instant(record[field]) > instant(record['retrieved_at']):
                raise ValueError('Later publication/correction than retrieval')
        if record['observation_type'] == 'inference' and record['inference_method'] is None:
            raise ValueError('Inference needs method')
        if any(record[k] is None for k in ('publication_at', 'event_at', 'available_at')) and not record['unknown_reason']:
            raise ValueError('Unknown timestamp needs reason')
        if record['observation_type'] in {'closing_price', 'settled_outcome'} and record['role'] != 'evaluation':
            raise ValueError('Evaluation leakage')
        if record['available_at'] is not None:
            if record['availability_ref'] is None:
                raise ValueError('Availability needs evidence')
            evidence = parent(record['availability_ref'], {'availability'})
            if evidence['source_ref'] != record['source_ref'] or evidence['available_at'] != record['available_at']:
                raise ValueError('Availability evidence mismatch')
            if evidence['evidence']['sha256'] != record['raw']['sha256']:
                raise ValueError('Availability raw content mismatch')
            for field in ('publication_at', 'corrected_at'):
                if record[field] and instant(record[field]) > instant(record['available_at']):
                    raise ValueError('Later publication/correction masquerading as earlier fact')
        elif record['availability_ref'] is not None:
            raise ValueError('Unknown availability contradicts evidence')
    elif kind == 'feature':
        parents = [parent(r, {'observation', 'feature'}) for r in record['parents']]
        times = [p['available_at'] for p in parents]
        expected = max(times, key=instant) if all(times) else None
        if record['available_at'] != expected:
            raise ValueError('Feature availability must equal latest input availability')
        if record['role'] == 'decision' and any(p['role'] != 'decision' for p in parents):
            raise ValueError('Evaluation leakage through feature')
    elif kind == 'manifest':
        members = parent(record['membership_ref'], {'membership'})
        inputs = [parent(r, {'observation', 'feature'}) for r in record['inputs']]
        rows = json.loads(blob(root, record['snapshot']))
        if not isinstance(rows, list) or len(rows) != record['row_count'] or len(members['samples']) != len(rows) or len(inputs) != len(rows):
            raise ValueError('Row/membership/input count mismatch')
        expected_rows = [{'sample': sample, 'value': item['value']} for sample, item in zip(members['samples'], inputs)]
        if canonical(rows) != canonical(expected_rows):
            raise ValueError('Snapshot is not reconstructible from membership and inputs')
        for ref in record['parent_manifests']:
            p = parent(ref, {'manifest'})
            if record['purpose'] == 'decision' and (p['purpose'] != 'decision' or instant(p['decision_at']) > instant(record['decision_at'])):
                raise ValueError('Unsafe parent manifest')
        if record['purpose'] == 'decision':
            for item in inputs:
                if item['role'] != 'decision':
                    raise ValueError('Evaluation leakage')
                if item['available_at'] is None or instant(item['available_at']) > instant(record['decision_at']):
                    raise ValueError('Unknown or late availability')


def permission_check(root: Path, source: dict, now: datetime | None = None) -> None:
    from .validate import read, instant
    now = now or datetime.now(timezone.utc)
    if not source['allowed_uses'] or source['terms_checked_at'] is None or not source['access_evidence']:
        raise ValueError('Permission evidence unavailable')
    uses = set()
    for path in source['access_evidence']:
        p = safe_path(root, path)
        if p not in root.resolve().glob(DATA_LOCATIONS['permission']):
            raise ValueError('Permission must be typed evidence')
        r = read(p)
        validate_data(root, 'permission', r, now=now)
        if p.name != f"{r['id']}.v{r['version']}.json":
            raise ValueError('Permission filename mismatch')
        if (r['source_id'], r['source_version'], r['source_url']) != (source['id'], source['version'], source['url']):
            raise ValueError('Permission source mismatch')
        if r['decision'] != 'PERMITTED' or r['reviewed_at'] != source['terms_checked_at'] or instant(r['valid_until']) <= now:
            raise ValueError('Permission denied, unverified, stale or review mismatch')
        uses.update(r['allowed_uses'])
    if not set(source['allowed_uses']) <= uses:
        raise ValueError('Uses outside permission evidence')


def acyclic(graph: dict[str, set[str]]) -> None:
    done, visiting = set(), set()
    def visit(node: str) -> None:
        if node not in graph:
            raise ValueError('Orphan dependency: ' + node)
        if node in visiting:
            raise ValueError('Dependency cycle: ' + node)
        if node in done:
            return
        visiting.add(node)
        for p in graph[node]:
            visit(p)
        visiting.remove(node)
        done.add(node)
    for node in graph:
        visit(node)


def quarantine(graph: dict[str, set[str]], scope: dict, retained: set[str] | None = None) -> set[str]:
    """No release API: Risk must authorize clearing and revalidated descendants."""
    acyclic(graph)
    if set(scope) != {'kind', 'targets'} or scope['kind'] not in {'global', 'records'} or not isinstance(scope['targets'], list):
        raise ValueError('Missing/unreadable typed scope')
    targets = set(scope['targets'])
    if scope['kind'] == 'global':
        if targets:
            raise ValueError('Global scope has no targets')
        targets = set(graph)
    elif not targets or not targets <= graph.keys():
        raise ValueError('Unknown/empty quarantine scope')
    blocked = targets | (retained or set())
    if not blocked <= graph.keys():
        raise ValueError('Unknown retained quarantine')
    while True:
        expanded = blocked | {n for n, parents in graph.items() if parents & blocked}
        if expanded == blocked:
            return blocked
        blocked = expanded


def history_inventory(root: Path, baseline: str) -> dict[str, str]:
    """Caller selects trusted full commit, never candidate records or moving refs."""
    if not re.fullmatch('[0-9a-f]{40}', baseline):
        raise ValueError('Verifier-selected full baseline SHA required')
    def git(*args: str) -> bytes:
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)
    if git('rev-parse', baseline + '^{commit}').decode().strip() != baseline:
        raise ValueError('Baseline is not exact commit')
    paths = git('ls-tree', '-r', '--name-only', baseline).decode().splitlines()
    return {p: digest(git('show', f'{baseline}:{p}')) for p in paths if p.startswith(IMMUTABLE_PREFIXES)}


def verify_history(root: Path, baseline: str | None, expected_inventory: dict[str, str] | None = None) -> dict[str, str]:
    if baseline is None:
        raise ValueError('History assurance unavailable: trusted baseline required')
    inventory = history_inventory(root, baseline)
    if expected_inventory is not None and inventory != expected_inventory:
        raise ValueError('Baseline replacement/inventory mismatch')
    for p, sha in inventory.items():
        if digest(safe_path(root, p).read_bytes()) != sha:
            raise ValueError('Published history mutated: ' + p)
    return inventory


def verify_checkpoint(root: Path, checkpoint: dict, trusted_digest: str, predecessor_digest: str) -> None:
    """Acceptance comes from verifier, never from an author-controlled status field."""
    if set(checkpoint) != {'baseline', 'inventory', 'predecessor_sha256'} or digest(canonical(checkpoint)) != trusted_digest:
        raise ValueError('Unaccepted checkpoint')
    if checkpoint['predecessor_sha256'] != predecessor_digest:
        raise ValueError('Checkpoint predecessor mismatch')
    verify_history(root, checkpoint['baseline'], checkpoint['inventory'])


def registry_checks(root: Path, records: dict[str, tuple[str, dict]], *,
                    now: datetime | None = None) -> dict[str, set[str]]:
    """Exact version graph; legacy handoff ID edges remain readable, not release proof."""
    graph = {p: set() for p in records}
    versions: dict[tuple[str, str], list[int]] = {}
    handoffs: dict[str, set[str]] = {}
    for path, (kind, record) in records.items():
        if 'id' not in record or kind in {'risk-policy', 'bankroll'}:
            continue
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]*', record['id']):
            raise ValueError('Invalid identifier: ' + path)
        if Path(path).name != f"{record['id']}.v{record['version']}.json":
            raise ValueError('Identity/filename mismatch: ' + path)
        versions.setdefault((kind, record['id']), []).append(record['version'])
        if kind == 'handoff':
            handoffs.setdefault(record['id'], set()).update(record['depends_on'])
        if kind == 'experiment':
            for ref in record['dataset_manifests']:
                if ref not in records or records[ref][0] != 'manifest':
                    raise ValueError('Missing/wrong-type experiment manifest')
                graph[path].add(ref)
        supersedes = record.get('supersedes')
        if kind in {'audit', 'hypothesis'} and record['version'] > 1 and supersedes is None:
            raise ValueError('Correction requires predecessor')
        if isinstance(supersedes, str):
            if supersedes not in records or records[supersedes][0] != kind:
                raise ValueError('Missing/wrong-type supersession')
            prior = records[supersedes][1]
            if prior['id'] != record['id'] or prior['version'] != record['version'] - 1:
                raise ValueError('Supersession must name previous exact version')
            graph[path].add(supersedes)
        def edges(value: object) -> None:
            if isinstance(value, dict):
                if set(value) == {'path', 'kind', 'id', 'version', 'sha256'}:
                    exact(root, value, set(DATA_LOCATIONS) | {k for k, _ in records.values()}, now=now)
                    if value['path'] not in records:
                        raise ValueError('Orphan typed dependency')
                    graph[path].add(value['path'])
                else:
                    for child in value.values():
                        edges(child)
            elif isinstance(value, list):
                for child in value:
                    edges(child)
        edges(record)
    for key, values in versions.items():
        if sorted(values) != list(range(1, max(values) + 1)):
            raise ValueError('Version gap: ' + str(key))
    acyclic(handoffs)
    acyclic(graph)
    return graph
