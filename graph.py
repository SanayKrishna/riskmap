"""Risk interdependency — link validation, cascade ranking, network chart."""

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


def network_chart(analysis):
    """Plotly dependency network, inline HTML div. Empty string if no links."""
    from plotly.offline import plot
    import plotly.graph_objects as go

    risks = analysis.get("risks", [])
    if not any(r.get("triggers") for r in risks):
        return ""
    g = build_graph(risks)
    pos = nx.spring_layout(g, seed=42)
    edge_x, edge_y = [], []
    for a, b in g.edges:
        edge_x += [pos[a][0], pos[b][0], None]
        edge_y += [pos[a][1], pos[b][1], None]
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(x=edge_x, y=edge_y, mode="lines",
                   line=dict(color="#C9C7BE", width=1.5),
                   hoverinfo="skip", showlegend=False)
    )
    for node in g.nodes:
        n = g.nodes[node]
        down = sorted(nx.descendants(g, node))
        fig.add_trace(
            go.Scatter(
                x=[pos[node][0]], y=[pos[node][1]],
                mode="markers+text",
                marker=dict(color=n.get("color", "#6B7280"), size=30,
                            line=dict(color="white", width=2)),
                text=[node], textposition="middle center",
                textfont=dict(color="white", size=11),
                name=node,
                hovertemplate=(
                    f"<b>{node}</b> — {n.get('title', '')}<br>"
                    f"Score {n.get('score', '')} ({n.get('severity', '')})<br>"
                    + (f"Triggers: {', '.join(down)}" if down else "No downstream links")
                    + "<extra></extra>"
                ),
                showlegend=False,
            )
        )
    fig.update_layout(
        title=f"{analysis.get('project_name', 'Project')} — Dependency Map",
        margin=dict(l=20, r=20, t=60, b=20),
        plot_bgcolor="white", paper_bgcolor="white",
        xaxis=dict(visible=False), yaxis=dict(visible=False),
    )
    return plot(fig, output_type="div", include_plotlyjs=False)
