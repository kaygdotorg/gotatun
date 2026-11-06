# SPDX-License-Identifier: AGPL-3.0-only
"""Summarize the final allocator snapshot in each cumulative daemon log."""
import json, re
from pathlib import Path
root = Path('/home/claude/j324/evidence')
result = {}
for label in ('heap-base', 'heap-candidate'):
    directory = root / label / label / 'mesh-gotatun'
    rows = {}
    if not directory.exists():
        continue
    for path in sorted(directory.glob('heap-*.log')):
        source = path.read_text(errors='replace')
        decoder = json.JSONDecoder()
        snapshots = []
        for match in re.finditer(r'\{\s*"jemalloc"\s*:', source):
            value, used = decoder.raw_decode(source[match.start():])
            snapshots.append(value['jemalloc'])
        if not snapshots:
            raise RuntimeError(f'No allocator JSON in {path}')
        final = snapshots[-1]
        stats = final['stats']
        bins = final['arenas']['bin']
        merged = final['stats.arenas']['merged']
        rows[path.name] = {
            'stats': {k: stats.get(k) for k in ('allocated','active','metadata','resident','mapped','retained')},
            'config': final.get('config'), 'opt': final.get('opt'),
            'small_bins': [{'size': b['size'], 'allocated': b['size'] * s['curregs'], 'curregs': s['curregs']} for b,s in zip(bins,merged['bins']) if s['curregs']],
            'large': merged.get('large'),
            'large_extents': [{'size': b['size'], 'allocated': b['size'] * s['curlextents'], 'count': s['curlextents']} for b,s in zip(final['arenas']['lextent'],merged['lextents']) if s['curlextents']],
            'types': sorted(set(line for line in source.splitlines() if line.startswith('J324_TYPE'))),
        }
    result[label] = rows
output = root / 'heap-summary.json'
output.write_text(json.dumps(result, indent=2)+'\n')
for label,rows in result.items():
    for phase in ('idle-1','loaded-scale-1','recovered-1','idle-100','loaded-scale-100','recovered-100','idle-1000','loaded-scale-1000','recovered-1000'):
        selected=[rows[f'heap-{phase}-{side}.log'] for side in ('a','b')]
        totals={k:sum(row['stats'][k] for row in selected) for k in ('allocated','active','metadata','resident','retained')}
        print(label,phase,totals)
print(output)
