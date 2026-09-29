"""Offline M0.2 orchestration safety decisions; deliberately no executor."""
from __future__ import annotations
import subprocess
from pathlib import Path
from .validate import read

ALLOWED = frozenset({'ORCHESTRATION_SCHEMA','HANDOFF_PARSING','REPOSITORY_PREFLIGHT','CLAIM_COORDINATION','COMPLETION_ROUTING','RELEASE_ROUTING','STOP_SCHEDULER_CHECK','AUDIT_LOGGING','SYNTHETIC_TEST','PLUGIN_REGISTRY_SCHEMA','PLUGIN_REVIEW_METADATA'})
PROHIBITED = frozenset({'SCOUT_DISCOVERY','EXTERNAL_INGESTION','RESEARCH_CAMPAIGN','QUANT_REAL_EXPERIMENT','PAPER_PORTFOLIO','LIVE_EXECUTION','CAPITAL_MUTATION','NETWORK_EXECUTION_ADAPTER','PLUGIN_INSTALL','CREDENTIAL_PROVISIONING','EXTERNAL_SOURCE_ACQUISITION'})
EXPECTED_REMOTE = 'https://github.com/dylanlaewe/EdgeLab.git'

def _remote(root: Path) -> str:
    return subprocess.run(['git','-C',str(root),'remote','get-url','origin'], text=True, capture_output=True, check=False).stdout.strip()

def preflight(root: Path) -> None:
    if not (root/'AGENTS.md').is_file() or not (root/'PROJECT_CONSTITUTION.md').is_file(): raise ValueError('Repository marker missing')
    if _remote(root) != EXPECTED_REMOTE: raise ValueError('Repository identity mismatch')

def decision(root: Path, task: dict, *, completed: set[str], writer_task: str|None=None, capability: dict|None=None) -> dict:
    """Return an auditable dispatch/deny result; never invokes an agent."""
    try:
        preflight(root)
        state=read(root/'docs/project-state.json'); stop=read(root/'reports/stops/STOP-M0-001.v1.json')
        action=task.get('action_classification')
        if action not in ALLOWED: raise ValueError('Unknown or prohibited action classification')
        if task.get('milestone')!='M0.2' or state['phase']!='M0' or state['status']!='BLOCKED_FOR_APPROVAL_REMEDIATION_ALLOWED': raise ValueError('Project state does not permit sandbox task')
        if stop.get('status')!='OPEN': raise ValueError('Unexpected STOP state denies sandbox dispatch')
        if task.get('handoff_ref')!='docs/handoffs/H-M0-027.v2.json': raise ValueError('Stale or superseded handoff')
        if set(task.get('dependencies',[]))-completed: raise ValueError('Unmet dependency')
        if writer_task and writer_task!=task.get('task_id'): raise ValueError('Writer slot conflict')
        if task.get('review_required') and task.get('reviewer_role')==task.get('assigned_role'): raise ValueError('Self-review denied')
        if capability and (capability.get('approval_status')!='APPROVED' or capability.get('revoked') or capability.get('executable_code')): raise ValueError('Capability cannot dispatch or activate')
        return {'decision':'DISPATCH','task_id':task['task_id'],'action':action,'reason':'Synthetic M0.2 allowlist satisfied','execution_adapter':'MOCK_ONLY'}
    except Exception as error:
        return {'decision':'DENY','task_id':task.get('task_id'),'reason':str(error),'execution_adapter':'MOCK_ONLY'}

def completion(task: dict, *, claim_task: str, evidence: list[str], reviewer_decision: str|None=None) -> str:
    if claim_task != task['task_id'] or not evidence: raise ValueError('Completion lacks current claim or evidence')
    if task['review_required']:
        if reviewer_decision=='REJECT': return 'ROUTE_REMEDIATION'
        if reviewer_decision=='APPROVE': return 'READY_FOR_DIRECTOR_GATE'
        return 'ROUTE_INDEPENDENT_REVIEW'
    return 'COMPLETED'
