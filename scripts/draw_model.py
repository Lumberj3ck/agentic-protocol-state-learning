"""Draw a learned Mealy machine as a readable, simplified Graphviz graph.

    uv run python scripts/draw_model.py results/runs/wolfssh-v3vm/model.dot results/figures/wolfssh.dot

Simplifications (the full model has one edge per state and input):
- each node is named by the last inputs of its shortest access path (the full path is in the tooltip);
- self-loops are not drawn; the node shows how many inputs loop;
- the state where the connection is gone (every input answers NO_CONN) is one node, and all edges into it
  from a state are merged into one dashed edge with a count;
- parallel edges between two states are merged; up to 3 input/output labels are shown, then "+N".
Render with Graphviz: dot -Tpng out.dot -o out.png
"""

import sys
from collections import defaultdict, deque

from aalpy.utils import load_automaton_from_file


def access(m):
    seen = {m.initial_state: ()}
    q = deque([m.initial_state])
    while q:
        s = q.popleft()
        for a in sorted(s.transitions):
            t = s.transitions[a]
            if t not in seen:
                seen[t] = seen[s] + (a,)
                q.append(t)
    return seen


def short(o):
    return o.replace("KEX31+NEWKEYS", "KEX31+NK").replace("UA_SUCCESS", "UA_OK").replace("+GLOBAL_REQUEST", "")


def main(src, dst, title=None):
    m = load_automaton_from_file(src, "mealy")
    acc = access(m)
    dead = {s for s in m.states if all(s.output_fun[a] == "NO_CONN" and s.transitions[a] is s for a in s.transitions)}
    ids = {s: f"n{i}" for i, s in enumerate(sorted(acc, key=lambda s: (len(acc[s]), acc[s])))}
    lines = ["digraph G {", '  rankdir=LR; nodesep=0.35; ranksep=0.55;',
             '  node [shape=box style="rounded,filled" fillcolor="#f6f3ee" color="#8a8378" fontname="Helvetica" fontsize=11];',
             '  edge [fontname="Helvetica" fontsize=9 color="#6b665d"];']
    if title:
        lines.append(f'  labelloc=t; label="{title}"; fontname="Helvetica"; fontsize=16;')
    for s, path in acc.items():
        loops = sum(1 for a in s.transitions if s.transitions[a] is s)
        if s in dead:
            label, extra = "connection closed\\n(all inputs: NO_CONN)", ' fillcolor="#f2d6d3" color="#b3261e"'
        elif s is m.initial_state:
            label, extra = f"start\\n{loops} inputs loop", ' fillcolor="#e1ebf7" color="#2d5f9a" penwidth=2'
        else:
            tail = " ".join(path[-3:])
            label, extra = f"…{tail}\\n{loops} inputs loop" if len(path) > 3 else f"{tail}\\n{loops} inputs loop", ""
        lines.append(f'  {ids[s]} [label="{label}" tooltip="{" ".join(path) or "start"}"{extra}];')
    for s in acc:
        if s in dead:
            continue
        groups = defaultdict(list)
        for a in sorted(s.transitions):
            t = s.transitions[a]
            if t is not s:
                groups[t].append(f"{a}/{short(s.output_fun[a])}")
        for t, labs in groups.items():
            if t in dead:
                lines.append(f'  {ids[s]} -> {ids[t]} [style=dashed color="#c9a39f" fontcolor="#9a5a52" label="{len(labs)} inputs"];')
            else:
                shown = "\\n".join(labs[:3]) + (f"\\n+{len(labs) - 3} more" if len(labs) > 3 else "")
                lines.append(f'  {ids[s]} -> {ids[t]} [label="{shown}"];')
    lines.append("}")
    open(dst, "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
