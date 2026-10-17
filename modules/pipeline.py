"""Dependency-ordered scan stages with resumable, atomic checkpoints."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Tool:
    name: str
    stage: str
    applicable: Callable
    run: Callable


def execute(tools, state, selected, workers, checkpoint, emit):
    for stage in dict.fromkeys(tool.stage for tool in tools):
        emit(type="phase", name=stage, label=stage.replace('_', ' ').title())
        pending = []
        for tool in (t for t in tools if t.stage == stage):
            previous = state.get(tool.name, {})
            if tool.name not in selected:
                state[tool.name] = {"status": "skipped", "error": "Skipped — not selected."}
            elif not tool.applicable(state):
                state[tool.name] = {"status": "skipped", "error": "Skipped — required services not found."}
            elif previous and previous.get('status') == 'ok' and not previous.get('error'):
                emit(type="task", name=tool.name, status="ok", detail="resumed from checkpoint", result=previous)
                continue
            else:
                pending.append(tool)
                continue
            emit(type="task", name=tool.name, status="skipped", detail=state[tool.name]['error'], result=state[tool.name])
        checkpoint(state)
        if not pending:
            continue
        # A refreshed upstream stage invalidates old downstream checkpoints.
        later = False
        for tool in tools:
            if tool.stage == stage:
                later = True
            elif later:
                state.pop(tool.name, None)
        checkpoint(state)
        def invoke(tool):
            emit(type="task", name=tool.name, status="running", detail="")
            try:
                result = tool.run(state)
                return {**result, 'status': 'error' if result.get('error') else 'ok'}
            except Exception as exc:
                return {'status': 'error', 'error': f'{type(exc).__name__}: {exc}'}
        with ThreadPoolExecutor(max_workers=min(workers, len(pending))) as pool:
            futures = {pool.submit(invoke, tool): tool for tool in pending}
            for future in as_completed(futures):
                tool = futures[future]
                state[tool.name] = future.result()
                checkpoint(state)
                emit(type="task", name=tool.name, status=state[tool.name]['status'],
                     detail=state[tool.name].get('error') or 'completed', result=state[tool.name])
        if stage == 'discovery' and state.get('nmap', {}).get('error'):
            for tool in tools:
                if tool.stage != 'discovery':
                    state[tool.name] = {'status': 'skipped', 'error': 'Skipped — discovery failed.'}
                    emit(type='task', name=tool.name, status='skipped', detail=state[tool.name]['error'], result=state[tool.name])
            checkpoint(state)
            break
    return state
