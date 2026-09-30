#!/usr/bin/env python3
"""
Generate a graphical abstract (PNG) for the Telegram Nmap Scanner Bot.

Renders a 7-layer vertical pipeline with per-layer colour coding and
two-lane data-flow arrows (forward request lane / return result lane).

Requires:  the `graphviz` Python package AND the `dot` binary on PATH.
Output:    /home/alireza/nmap-bot/graphical_abstract.png (overridable via argv[1])
"""

import sys
import graphviz

OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/alireza/nmap-bot/graphical_abstract.png"

# Catppuccin Mocha palette on a #1e1e2e base
BG = "#1e1e2e"
FG = "#cdd6f4"
MUTED = "#a6adc8"
BORDER = "#45475a"
LANE_FWD = "#89b4fa"
LANE_RET = "#f9e2af"

# (node id, layer title, accent colour, [detail lines])
LAYERS = [
    ("user", "USER LAYER", "#89b4fa", [
        "Telegram App",
        "/scan command",
        "/start command",
        "Output: Text or File",
    ]),
    ("network", "NETWORK LAYER", "#94e2d5", [
        "Telegram API  (api.telegram.org)",
        "V2Ray Proxy  (VLESS, SOCKS5 :10808)",
        "Censorship Circumvention",
    ]),
    ("host", "UBUNTU HOST", "#a6e3a1", [
        "Ubuntu 25.10",
        "IP: 192.168.174.128",
        "SSH Port 22",
        "Docker 29.7.2",
    ]),
    ("docker", "DOCKER CONTAINER", "#cba6f7", [
        "Image: nmap-bot",
        "Base: python:3.11-slim",
        "ENV: TELEGRAM_BOT_TOKEN",
    ]),
    ("app", "APPLICATION LAYER", "#f9e2af", [
        "Python 3.11",
        "python-telegram-bot 21.6",
        "Handlers: /start, /scan",
    ]),
    ("scanner", "SCANNER LAYER", "#fab387", [
        "nmap 7.95",
        "nmap -F -T4 <target>",
        "Fast Scan (Top 100 Ports)",
    ]),
    ("target", "TARGET", "#f38ba8", [
        "8.8.8.8",
        "scanme.nmap.org",
    ]),
]

# Forward-flow captions for each hop down the stack
HOP_LABELS = [
    "/scan",
    "HTTPS API",
    "VLESS tunnel",
    "docker exec",
    "handler",
    "fork/exec",
]


def esc(s: str) -> str:
    """Escape for a Graphviz HTML-like label string literal."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def card(title: str, accent: str, lines: list) -> str:
    """Build an HTML-like table label that renders as a coloured card."""
    rows = [
        f'<TR><TD BGCOLOR="{accent}" ALIGN="CENTER">'
        f'<FONT COLOR="{BG}" POINT-SIZE="14"><B>{esc(title)}</B></FONT></TD></TR>'
    ]
    for ln in lines:
        rows.append(
            f'<TR><TD ALIGN="LEFT" BALIGN="LEFT">'
            f'<FONT COLOR="{FG}" POINT-SIZE="11">{esc(ln)}</FONT></TD></TR>'
        )
    body = "".join(rows)
    return (
        f'<TABLE BORDER="1" CELLBORDER="1" CELLSPACING="0" CELLPADDING="9" '
        f'COLOR="{BORDER}" BGCOLOR="#313244">'
        f'{body}</TABLE>'
    )


def build() -> graphviz.Digraph:
    g = graphviz.Digraph(
        name="telegram_nmap_bot_abstract",
        format="png",
    )
    g.attr(rankdir="TB", bgcolor=BG, pad="0.5", nodesep="0.30", ranksep="0.52")
    g.attr(
        "node",
        shape="none",
        fontname="Helvetica",
        margin="0",
    )
    g.attr(
        "edge",
        fontname="Helvetica",
        fontsize="10",
        fontcolor=MUTED,
        color=LANE_FWD,
        arrowsize="0.85",
        penwidth="1.6",
    )

    # ---- Title -------------------------------------------------------
    g.node(
        "title",
        shape="plaintext",
        fontcolor=FG,
        fontsize="21",
        label=(
            f'<<B>Telegram Nmap Scanner Bot</B><BR ALIGN="CENTER"/>'
            f'<FONT POINT-SIZE="13" COLOR="{MUTED}">'
            f'Automated Network Scanning via Chat</FONT>>'
        ),
    )

    # ---- Layer cards -------------------------------------------------
    ids = []
    for node_id, title, accent, lines in LAYERS:
        g.node(node_id, label=f"<{card(title, accent, lines)}>")
        ids.append(node_id)

    # Title on top of the stack
    g.edge("title", ids[0], style="invis")

    # ---- Forward lane (left): top -> bottom --------------------------
    for i, hop in enumerate(HOP_LABELS):
        g.edge(
            ids[i],
            ids[i + 1],
            label=hop,
            tailport="w",
            headport="w",
            color=LANE_FWD,
            dir="forward",
        )

    # ---- Return lane (right): bottom -> top --------------------------
    for i in range(len(ids) - 2, -1, -1):
        g.edge(
            ids[i + 1],
            ids[i],
            tailport="e",
            headport="e",
            color=LANE_RET,
            style="dashed",
            fontcolor=LANE_RET,
            constraint="false",
        )
    # Label the outermost return edge only, to keep the layout readable
    g.edge(
        ids[-1],
        ids[0],
        tailport="e",
        headport="e",
        color=LANE_RET,
        style="dashed",
        fontcolor=LANE_RET,
        label="result returned",
        constraint="false",
    )

    return g


def main() -> int:
    g = build()
    path = g.render(
        filename=OUT.rsplit(".", 1)[0],
        format="png",
        cleanup=True,
    )
    print(f"wrote: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())