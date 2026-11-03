"""Risk interdependency — link validation, cascade ranking, SVG dependency map."""

import networkx as nx

SEV_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def validate_links(risks):
    """Cross-check triggers against real ids. Raises ValueError."""
    ids = {r["id"] for r in risks}
    for r in risks:
        for t in r.get("triggers", []) or []:
            if t == r["id"]:
                raise ValueError(f"risk {r['id']!r} cannot trigger itself")
            if t not in ids:
                raise ValueError(
                    f"risk {r['id']!r} triggers unknown risk {t!r}"
                )
    return True


def build_graph(risks):
    g = nx.DiGraph()
    for r in risks:
        g.add_node(r["id"], title=r.get("title", ""), severity=r.get("severity", ""),
                   score=r.get("score", 0), color=r.get("color", "#6B7280"))
    for r in risks:
        for t in r.get("triggers", []) or []:
            g.add_edge(r["id"], t)
    return g


def isolated_nodes(risks):
    """Risks with no links in either direction (float free on the map)."""
    linked = set()
    for r in risks:
        for t in r.get("triggers", []) or []:
            linked.add(r["id"])
            linked.add(t)
    return [r for r in risks if r["id"] not in linked]


def cascade_ranking(risks):
    """Risks ordered by downstream blast radius. Empty list when no links."""
    g = build_graph(risks)
    sev = {r["id"]: r.get("severity", "Low") for r in risks}
    ranked = []
    for node in g.nodes:
        downstream = sorted(nx.descendants(g, node))
        if not downstream:
            continue
        ranked.append(
            {
                "id": node,
                "title": g.nodes[node].get("title", ""),
                "downstream": downstream,
                "blast": len(downstream),
                "max_downstream_severity": max(
                    (sev.get(d, "Low") for d in downstream),
                    key=lambda s: SEV_WEIGHT.get(s, 0),
                ),
            }
        )
    ranked.sort(key=lambda c: (-c["blast"], c["id"]))
    return ranked


def chains_text(risks, max_depth=3):
    """Human-readable trigger chains for the AI prompt."""
    g = build_graph(risks)
    titles = {r["id"]: r.get("title", "") for r in risks}
    lines = []
    for r in risks:
        if not (r.get("triggers") or []):
            continue
        # BFS paths out of r up to max_depth
        paths = [[r["id"]]]
        done = []
        for _ in range(max_depth):
            nxt = []
            for p in paths:
                extended = False
                for t in g.successors(p[-1]):
                    if t in p:  # cycle guard
                        continue
                    nxt.append(p + [t])
                    extended = True
                if not extended:
                    done.append(p)
            paths = nxt or done
            if not nxt:
                break
        for p in (paths + done):
            if len(p) > 1:
                lines.append(
                    " → ".join(f"{n} ({titles.get(n, '')})" for n in p)
                )
    return sorted(set(lines))


# ── Dependency map: server-rendered SVG ─────────────────────────────────────
NODE_W, NODE_H = 212, 58
COL_GAP, ROW_GAP, PAD = 96, 22, 24
LABEL_H = 30  # caption row above the "not linked" nodes


def _layers(g):
    """Left-to-right layers (longest path from a source). Cycles are broken by
    dropping back edges for layout only; those edges are still drawn."""
    dag = nx.DiGraph(g)
    while True:
        try:
            cyc = nx.find_cycle(dag)
        except nx.NetworkXNoCycle:
            break
        dag.remove_edge(*cyc[-1][:2])
    return [list(gen) for gen in nx.topological_generations(dag)]


def _order_layers(layers, g, score):
    """Order nodes inside each layer by the mean slot of their parents
    (cuts crossings), then by score desc, id."""
    slot = {}
    for li, layer in enumerate(layers):
        if li == 0:
            layer.sort(key=lambda n: (-score.get(n, 0), n))
        else:
            def bary(n):
                ps = [slot[p] for p in g.predecessors(n) if p in slot]
                return sum(ps) / len(ps) if ps else 1e9
            layer.sort(key=lambda n: (bary(n), -score.get(n, 0), n))
        for k, n in enumerate(layer):
            slot[n] = k
    return layers


def _clip(text, n):
    text = text or ""
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def network_chart(analysis):
    """Dependency map as an inline SVG fragment. Empty string if no links."""
    from html import escape

    risks = analysis.get("risks", [])
    if not any(r.get("triggers") for r in risks):
        return ""
    g = build_graph(risks)
    by_id = {r["id"]: r for r in risks}
    score = {r["id"]: r.get("score", 0) for r in risks}
    linked_ids = {n for n in g.nodes if g.degree(n) > 0}
    lone = [r for r in risks if r["id"] not in linked_ids]
    sub = g.subgraph(linked_ids).copy()

    layers = _order_layers(_layers(sub), sub, score)
    tallest = max(len(layer) for layer in layers)
    col_h = tallest * NODE_H + (tallest - 1) * ROW_GAP
    pos = {}  # id -> (x, y) top-left corner
    for li, layer in enumerate(layers):
        x = PAD + li * (NODE_W + COL_GAP)
        y0 = PAD + (col_h - (len(layer) * NODE_H + (len(layer) - 1) * ROW_GAP)) / 2
        for k, n in enumerate(layer):
            pos[n] = (x, y0 + k * (NODE_H + ROW_GAP))
    width = PAD * 2 + len(layers) * NODE_W + (len(layers) - 1) * COL_GAP
    height = PAD * 2 + col_h

    # unlinked risks: a labelled row under the graph, wrapped to the graph width
    lone_y0 = height
    if lone:
        per_row = max(1, int((width - PAD) // (NODE_W + 16)))
        rows = -(-len(lone) // per_row)
        for k, r in enumerate(lone):
            pos[r["id"]] = (PAD + (k % per_row) * (NODE_W + 16),
                            lone_y0 + LABEL_H + (k // per_row) * (NODE_H + ROW_GAP))
        height = lone_y0 + LABEL_H + rows * (NODE_H + ROW_GAP) + PAD - ROW_GAP

    out = [
        f'<div class="depmap-wrap"><svg class="depmap" style="width:{width}px" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Risk dependency map: arrows point from a risk to the risks it triggers">',
        '<defs><marker id="dep-arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="9" markerHeight="9" orient="auto-start-reverse">'
        '<path d="M0 0 L10 5 L0 10 z" class="dep-arrowhead"/></marker></defs>',
    ]
    # edges first so nodes sit on top of them. Right-angle connectors, like a schematic.
    for k, (a, b) in enumerate(sub.edges):
        ax, ay = pos[a]
        bx, by = pos[b]
        if bx > ax:  # forward: right edge -> left edge; stagger the vertical run per edge
            sx, sy, tx, ty = ax + NODE_W, ay + NODE_H / 2, bx, by + NODE_H / 2
            mx = sx + 24 + (k % 4) * 10 + ((bx - ax - NODE_W - COL_GAP) / (NODE_W + COL_GAP)) * 0
            path = f"M{sx:.1f} {sy:.1f} H{mx:.1f} V{ty:.1f} H{tx:.1f}"
        else:  # same column or back edge: exit the top, run above, drop into the target
            sx, sy = ax + NODE_W / 2, ay
            tx, ty = bx + NODE_W / 2, by
            top = min(sy, ty) - (16 + (k % 3) * 8)
            path = f"M{sx:.1f} {sy:.1f} V{top:.1f} H{tx:.1f} V{ty:.1f}"
        out.append(
            f'<path class="dep-edge" data-from="{escape(str(a))}" data-to="{escape(str(b))}" '
            f'd="{path}" marker-end="url(#dep-arrow)"/>'
        )
    if lone:
        out.append(f'<text class="dep-caption" x="{PAD}" y="{lone_y0 + 18}">NOT LINKED</text>')
    for n, (x, y) in pos.items():
        r = by_id[n]
        sev = r.get("severity", "Low")
        down = sorted(nx.descendants(g, n))
        tip = (f'{n} — {r.get("title", "")}\nScore {r.get("score", "")} ({sev})\n'
               + (f'Triggers: {", ".join(down)}' if down else "No downstream links"))
        out.append(
            f'<g class="dep-node sev-{escape(str(sev))}" data-id="{escape(str(n))}" '
            f'transform="translate({x:.1f} {y:.1f})"><title>{escape(tip)}</title>'
            f'<rect class="body" width="{NODE_W}" height="{NODE_H}"/>'
            f'<rect class="bar" width="6" height="{NODE_H}"/>'
            f'<text class="dep-id" x="18" y="23">{escape(str(n))}</text>'
            f'<text class="dep-score" x="{NODE_W - 12}" y="23" text-anchor="end">{escape(str(r.get("score", "")))}</text>'
            f'<text class="dep-title" x="18" y="43">{escape(_clip(str(r.get("title", "")), 27))}</text></g>'
        )
    out.append("</svg></div>")
    return "".join(out)
