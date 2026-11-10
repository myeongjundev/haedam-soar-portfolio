"""Deterministic canvas layout for generated n8n workflows. Changes node positions only.

Columns follow the longest path from the trigger; the child with the longest remaining
path keeps its parent's row and other branches drop to the next free row. Long flows wrap
into evenly sized bands so the canvas stays close to a 16:9 screen instead of one long
line. A shared exit (a node fed by 3+ branches, plus the plain chain after it, e.g. the
Respond to Webhook node of all hold branches) sits right of the bands, vertically centred.
"""
from math import ceil

DX, DY, BAND_GAP = 280, 180, 140
TARGET_RATIO = 16 / 9
WRAP_FROM = 9  # flows with more columns than this wrap into bands


def tidy(workflow):
    """Return the same workflow with tidy `position`s. A list-wrapped export is kept wrapped."""
    w = workflow[0] if isinstance(workflow, list) else workflow
    names = [n['name'] for n in w['nodes'] if not n['type'].endswith('stickyNote')]
    edges = [(s, i, e['node']) for s, out in w.get('connections', {}).items()
             for i, branch in enumerate(out.get('main', [])) for e in (branch or [])
             if s in names and e['node'] in names]
    back = _back_edges(names, edges)  # loop-closing edges stay connected; layering ignores them
    edges = [e for e in edges if (e[0], e[2]) not in back]
    children = {n: [] for n in names}
    parents = {n: [] for n in names}
    for s, i, d in edges:
        children[s].append((i, d))
        parents[d].append(s)
    order = _topological(names, children, parents)

    exits = []  # chains that start at a shared exit node
    in_exit = set()
    for n in order:
        if len(parents[n]) >= 3 and n not in in_exit:
            chain, cur = [n], n
            while len(children[cur]) == 1 and len(parents[children[cur][0][1]]) == 1:
                cur = children[cur][0][1]
                chain.append(cur)
            if not children[cur]:
                exits.append(chain)
                in_exit.update(chain)
    body = [n for n in order if n not in in_exit]

    depth = {n: 0 for n in names}
    for n in order:
        for _, d in children[n]:
            depth[d] = max(depth[d], depth[n] + 1)
    rest = {n: 0 for n in names}  # longest remaining path inside the body
    for n in reversed(order):
        rest[n] = max([rest[d] + 1 for _, d in children[n] if d not in in_exit] or [0])

    lane, used = {}, {}
    for n in body:
        if n not in lane:
            lane[n] = _free(used, depth[n], 0)
        kids = sorted({d for _, d in children[n] if d not in in_exit and d not in lane},
                      key=lambda d: (-rest[d], min(i for i, x in children[n] if x == d), names.index(d)))
        for k, d in enumerate(kids):
            lane[d] = _free(used, depth[d], lane[n] if k == 0 else lane[n] + 1)

    cols = max([depth[n] for n in body] or [0]) + 1
    exit_w = max([len(c) for c in exits] or [0]) * DX

    def bands_for(count):
        per = ceil(cols / count)
        rows = [sorted({lane[n] for n in body if depth[n] // per == b}) for b in range(count)]
        heights = [max(len(r), 1) * DY for r in rows]
        return per, rows, heights

    count = 1
    if cols > WRAP_FROM:
        def score(c):
            per, _, heights = bands_for(c)
            return abs((per * DX + exit_w) / (sum(heights) + (c - 1) * BAND_GAP) - TARGET_RATIO)
        count = min(range(1, ceil(cols / 4) + 1), key=lambda c: (round(score(c), 6), c))
    per, rows, heights = bands_for(count)
    tops = [sum(heights[:b]) + b * BAND_GAP for b in range(count)]
    pos = {}
    for n in body:
        band, col = divmod(depth[n], per)
        pos[n] = [col * DX, tops[band] + rows[band].index(lane[n]) * DY]
    total_h = tops[-1] + heights[-1]
    first = (total_h - len(exits) * DY) / 2
    for k, chain in enumerate(exits):
        for j, n in enumerate(chain):
            pos[n] = [(min(cols, per) + j) * DX, round((first + k * DY) / 20) * 20]
    for node in w['nodes']:
        if node['name'] in pos:
            node['position'] = pos[node['name']]
    return workflow


def _topological(names, children, parents):
    indeg = {n: len(parents[n]) for n in names}
    order, ready = [], [n for n in names if not indeg[n]]
    while ready:
        n = ready.pop(0)
        order.append(n)
        for _, d in children[n]:
            indeg[d] -= 1
            if not indeg[d]:
                ready.append(d)
    if len(order) != len(names):
        raise ValueError('workflow graph still has a cycle')
    return order


def _back_edges(names, edges):
    """Edges that return to a node on the current DFS path (retry or next-step loops)."""
    out = {n: [d for s, _, d in edges if s == n] for n in names}
    has_parent = {d for _, _, d in edges}
    state, back = {}, set()
    for root in [n for n in names if n not in has_parent] + names:
        if root in state:
            continue
        stack = [(root, iter(out[root]))]
        state[root] = 'open'
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                state[node] = 'done'
                stack.pop()
            elif state.get(nxt) == 'open':
                back.add((node, nxt))
            elif nxt not in state:
                state[nxt] = 'open'
                stack.append((nxt, iter(out[nxt])))
    return back


def _free(used, column, want):
    taken = used.setdefault(column, set())
    row = want
    while row in taken:
        row += 1
    taken.add(row)
    return row


def tidy_all(workflows):
    """Apply `tidy` to every workflow of a {filename: workflow} mapping."""
    for workflow in workflows.values():
        tidy(workflow)
    return workflows


if __name__ == '__main__':
    def node(name, kind='code'):
        return {'name': name, 'type': 'n8n-nodes-base.' + kind}
    chain = {'nodes': [node(f'n{i}') for i in range(20)] + [node('Respond', 'respondToWebhook')],
             'connections': {f'n{i}': {'main': [[{'node': f'n{i + 1}'}], [{'node': 'Respond'}]]} for i in range(19)}}
    chain['connections']['n19'] = {'main': [[{'node': 'Respond'}]]}
    p = {n['name']: tuple(n['position']) for n in tidy(chain)['nodes']}
    assert len(set(p.values())) == len(p), 'overlapping nodes'
    assert len({y for k, (_, y) in p.items() if k != 'Respond'}) > 1, 'long chain must wrap into bands'
    assert p['Respond'][0] > max(x for k, (x, _) in p.items() if k != 'Respond'), 'shared exit sits right of the bands'
    loop = {'nodes': [node('a'), node('b'), node('c')],
            'connections': {'a': {'main': [[{'node': 'b'}]]}, 'b': {'main': [[{'node': 'c'}]]}, 'c': {'main': [[{'node': 'a'}]]}}}
    assert tidy(loop)['nodes'][2]['position'][0] > 0, 'loops are laid out, not rejected'
    print('n8n_layout self-check ok')
