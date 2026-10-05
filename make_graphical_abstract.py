#!/usr/bin/env python3
"""
Generate the graphical abstract (PNG) for NetSentinel.

Supersedes the earlier seven-layer stack, which described the MVP: it showed
only a chat command reaching nmap, and predates the rule engine, the Mini App
and the web panel.

This version is organised around the property that actually distinguishes the
system -- **every scan is a policy decision first and a scan second** -- so the
path from each of the three entry surfaces to the scanner passes visibly
through authentication, authorisation and the rule engine.

LAYOUT DISCIPLINE (learned the hard way; do not undo)

Graphviz resolves conflicting constraints arbitrarily, so this figure keeps to
one rule: the spine is a single chain, and every multi-card rank is joined by
*invisible* edges only. Three specific earlier mistakes are called out below
because each one wrecked the layout:

  * `constraint=false` edges to a side node let it float to the top of the
    canvas, far from what it referred to. Background jobs are therefore in the
    spine, not floating beside it.
  * A `dir=none`/`weight` "choke point" node became an orphan on the right.
    The convergence statement is now a caption line inside the band it
    describes.
  * Cards on one rank with different line counts render staggered, because
    rank=same aligns them by their top edge. Every card in a row is padded to
    the same number of lines.

  * The idiom that actually puts cards side by side is a rank=same subgraph
    PLUS invisible edges with `constraint=false` between them. Without
    constraint=false those edges are real edges and silently force a vertical
    chain -- which is exactly what happened on the first two attempts, and it
    looks like rank=same was ignored rather than like a constraint conflict.

Requires:  the `graphviz` Python package AND the `dot` binary on PATH.
Output:    graphical_abstract.png next to this script (overridable via argv[1])

If graphviz is not installed on the host, render in a throwaway container:

    docker run --rm -v "$PWD:/w" -w /w --entrypoint bash python:3.11-slim -c \
      'apt-get update -qq && apt-get install -y -qq graphviz >/dev/null && \
       pip install -q graphviz && python make_graphical_abstract.py'

Every figure label is checked against the source it describes: core/profiles.py,
database/models.py (RULE_TYPES, CHANGE_TYPES), bot/app.py (command handlers) and
docker-compose.yml (services).
"""

import sys

import graphviz

OUT = sys.argv[1] if len(sys.argv) > 1 else "graphical_abstract.png"

# --------------------------------------------------------------------------
# Palette: Catppuccin Mocha on #1e1e2e.
#
# Blue marks the request path, teal identity, amber the policy decision, green
# execution, peach the external process, mauve persistence, pink what changed.
# Semantic hues are reserved: no decorative use of green or pink.
# --------------------------------------------------------------------------
BG = "#1e1e2e"
PANEL = "#313244"
FG = "#cdd6f4"
MUTED = "#a6adc8"
BORDER = "#45475a"

BLUE = "#89b4fa"
TEAL = "#94e2d5"
YELLOW = "#f9e2af"
GREEN = "#a6e3a1"
PEACH = "#fab387"
PINK = "#f38ba8"
MAUVE = "#cba6f7"

PAD = "&#160;" * 4  # keeps same-rank cards the same width


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def card(title: str, accent: str, lines: list, pad_to: int = 0) -> str:
    """An HTML-like table rendered as a card with an accent header.

    ``pad_to`` pads the body with blank rows so that cards sharing a rank are
    the same height; without it rank=same aligns them by their top edge and
    they render visibly staggered.
    """
    rows = [
        '<TR><TD BGCOLOR="%s" ALIGN="CENTER">'
        '<FONT COLOR="%s" POINT-SIZE="12"><B>%s</B></FONT></TD></TR>'
        % (accent, BG, esc(title))
    ]
    for line in list(lines) + [""] * (pad_to - len(lines)):
        rows.append(
            '<TR><TD ALIGN="LEFT" BALIGN="LEFT">'
            '<FONT COLOR="%s" POINT-SIZE="9">%s</FONT></TD></TR>'
            % (FG if line else BORDER, esc(line) if line else PAD)
        )
    return (
        '<TABLE BORDER="1" CELLBORDER="1" CELLSPACING="0" CELLPADDING="7" '
        'COLOR="%s" BGCOLOR="%s">%s</TABLE>' % (BORDER, PANEL, "".join(rows))
    )


def caption(text: str) -> str:
    """A short centred line that sits between two bands."""
    return (
        '<<FONT COLOR="%s" POINT-SIZE="9">%s</FONT>>'
        % (MUTED, esc(text))
    )


# --------------------------------------------------------------------------
# Bands. Widths are kept similar on purpose so the spine reads as one column.
# --------------------------------------------------------------------------

INTERFACE_LINES = 5

INTERFACES = [
    ("chat", "TELEGRAM CHAT", BLUE, [
        "16 bot commands",
        "/scan  /addtarget  /targets  /deltarget",
        "/status  /scans  /export  /report",
        "/schedule  /health  /cleanup  /app",
        "Chat reply, or a .txt report",
    ]),
    ("mini", "TELEGRAM MINI APP", BLUE, [
        "React SPA inside the chat WebView",
        "Menu button  ·  /app  ·  /start",
        "6 tabs: dashboard, targets, scan,",
        "changes, rules, settings",
        "No password, no SSH tunnel",
    ]),
    ("panel", "WEB ADMIN PANEL", BLUE, [
        "FastAPI service + React SPA at /admin",
        "Targets, users, rules, audit log",
        "Runtime settings, export and report",
        "Operators, on a trusted LAN",
        "Same database, separate identities",
    ]),
]

AUTH = ("AUTHENTICATION  ·  AUTHORISATION", TEAL, [
    "Chat       Telegram user id checked against the ALLOWED_USER_IDS allow-list",
    "Mini App   initData signature: HMAC-SHA256, key = \"WebAppData\", message = bot token;",
    "           compared in constant time; then freshness, then a disabled-account check",
    "Panel      bcrypt password, exchanged for a JWT in an HttpOnly cookie",
    "Roles      chat: viewer / operator / admin        panel: viewer / admin / superadmin",
    "Scope      every target re-checked against ALLOWED_CIDRS, at registration and again at scan time",
])

POLICY = ("RULE ENGINE  —  pure: no database, no DNS, no I/O", YELLOW, [
    "10 operator-managed rules, evaluated before every scan          (models.py: RULE_TYPES)",
    "CIDR family   ·   domain family   ·   port family   ·   limit and window family",
    "allow_cidr  deny_cidr  allow_domain  deny_domain  allow_port  deny_port",
    "max_scan_time  rate_limit  time_window  user_quota",
    "Deny always wins   ·   an allow rule that matches nothing denies   ·   a malformed rule is skipped",
    "Scope per rule:  global | user | target          every rule can be dry-run before it is saved",
])

EXEC = ("SCAN EXECUTION", GREEN, [
    "All three surfaces converge on one path, so no surface reaches the network",
    "without passing the engine. Two workers run it, one per container:",
    "the bot process and the admin process that serves the Mini App.",
    "ScanWorker  bounded queue   ·   ScanManager  rate limit, per-user quota, scoped target",
])

NMAP = ("NMAP  7.95", PEACH, [
    "quick      -F -T4                              top 100 ports",
    "service    -F -T4 -sV --version-intensity 2",
    "deep       -T4 -sV --top-ports 1000",
    "nmap -oX  →  xml_parser  →  host and service rows",
])

DIFF = ("CHANGE DETECTION", PINK, [
    "Every successful scan is diffed against the previous one",
    "for the same target:",
    "new_host    closed_host    new_port",
    "closed_port    service_change",
])

SIDE_LINES = 4

SIDE = [
    ("store", "PERSISTENCE", MAUVE, [
        "PostgreSQL, 13 tables",
        "targets, scans, hosts, services,",
        "change_events, schedules, rules,",
        "rule_hits, audit_log, settings, users",
    ]),
    ("alerts", "NOTIFICATION", PINK, [
        "Change events become Telegram",
        "alerts in the operator's own",
        "language, and a diff is visible in",
        "the Mini App and the panel",
    ]),
]

BACKGROUND = ("BACKGROUND JOBS", MUTED, [
    "Scheduler   per-target interval scans, on the same worker and under the same rules",
    "Retention   age limit and per-target scan cap, applied on a daily job",
    "Audit log   append-only; every action, from either surface, with its source IP",
])

FOOTER = ("Every request is authenticated, authorised, scope-checked and rate-limited "
          "before a single packet is sent.  ·  Nothing an operator does is unrecorded.")


def build() -> graphviz.Digraph:
    g = graphviz.Digraph(name="netsentinel_graphical_abstract", format="png")
    g.attr(rankdir="TB", bgcolor=BG, pad="0.4", nodesep="0.22", ranksep="0.40")
    g.attr("node", shape="none", fontname="Helvetica", margin="0")
    g.attr("edge", fontname="Helvetica", fontsize="8", fontcolor=MUTED,
           color=BLUE, arrowsize="0.65", penwidth="1.3")

    # ---- Title ---------------------------------------------------------
    g.node("title", shape="plaintext", fontcolor=FG, fontsize="20",
           label=('<<B>NetSentinel</B><BR ALIGN="CENTER"/>'
                  '<FONT POINT-SIZE="12" COLOR="%s">A policy-gated network '
                  'scanner for Telegram, with a Mini App and an operator panel'
                  '</FONT>>' % MUTED))

    # ---- Rank 1: three entry surfaces ----------------------------------
    ids = []
    with g.subgraph() as row:
        row.attr(rank="same")
        for node_id, title, accent, lines in INTERFACES:
            g.node(node_id, label="<%s>" % card(title, accent, lines, INTERFACE_LINES))
            ids.append(node_id)
        # Left-to-right order inside the rank. constraint=false is essential:
        # without it these are ordinary edges and force a vertical chain, so
        # the cards stack instead of sitting beside each other.
        for a, b in zip(ids, ids[1:]):
            g.edge(a, b, style="invis", weight="20", constraint="false")

    # Anchor the title to the CENTRE card, constrained, and to the outer two
    # without a constraint. Anchoring only to the leftmost card drags the
    # title and the whole figure to the left, leaving the spine off-centre.
    g.edge("title", ids[1], style="invis")
    for outer in (ids[0], ids[2]):
        g.edge("title", outer, style="invis", constraint="false", weight="2")

    # ---- Rank 2: authentication ---------------------------------------
    g.node("auth", label="<%s>" % card(AUTH[0], AUTH[1], AUTH[2]))
    # headport="n", not "w": entering the west edge pushes the band to the
    # right of its three sources, which is what left a wide empty margin beside
    # the spine. Entering the top edge lets it centre under the row.
    for iface in ids:
        g.edge(iface, "auth", tailport="s", headport="n",
               color=TEAL, fontcolor=TEAL, style="dashed", label="identify")

    # ---- Rank 3: the rule engine --------------------------------------
    g.node("policy", label="<%s>" % card(POLICY[0], POLICY[1], POLICY[2]))
    g.edge("auth", "policy", tailport="s", headport="n",
           color=YELLOW, fontcolor=YELLOW, penwidth="1.9",
           label="decide: allow, and under which limits")

    # ---- Rank 4: execution, with the convergence note inside the card --
    g.node("exec", label="<%s>" % card(EXEC[0], EXEC[1], EXEC[2]))
    g.edge("policy", "exec", tailport="s", headport="n",
           color=GREEN, fontcolor=GREEN, label="queued")

    # ---- Rank 5: nmap ---------------------------------------------------
    g.node("nmap", label="<%s>" % card(NMAP[0], NMAP[1], NMAP[2]))
    g.edge("exec", "nmap", tailport="s", headport="n",
           color=PEACH, fontcolor=PEACH)

    # ---- Rank 6: change detection --------------------------------------
    g.node("diff", label="<%s>" % card(DIFF[0], DIFF[1], DIFF[2]))
    g.edge("nmap", "diff", tailport="s", headport="n",
           color=PINK, fontcolor=PINK, label="parse and diff")

    # ---- Rank 7: persistence and notification, side by side ------------
    side_ids = []
    with g.subgraph() as row2:
        row2.attr(rank="same")
        for node_id, title, accent, lines in SIDE:
            g.node(node_id, label="<%s>" % card(title, accent, lines, SIDE_LINES))
            side_ids.append(node_id)
        g.edge(side_ids[0], side_ids[1], style="invis", weight="20",
               constraint="false")

    # Both drops leave the bottom of `diff`, so the two cards read as siblings
    # rather than as a chain from one to the other.
    g.edge("diff", side_ids[0], tailport="s", headport="n",
           color=MAUVE, fontcolor=MAUVE, label="persist")
    g.edge("diff", side_ids[1], tailport="s", headport="n",
           color=PINK, fontcolor=PINK, label="notify")

    # ---- Rank 8: background jobs, in the spine -------------------------
    g.node("bg", label="<%s>" % card(BACKGROUND[0], BACKGROUND[1], BACKGROUND[2]))
    for node_id in side_ids:
        g.edge(node_id, "bg", tailport="s", headport="n",
               color=MUTED, fontcolor=MUTED, style="dashed")

    # ---- Footer --------------------------------------------------------
    # caption() already returns a complete <...> HTML label, so it must not
    # be wrapped again -- <<FONT...>> is an invalid token to dot.
    g.node("footer", shape="plaintext", fontcolor=MUTED, fontsize="10",
           label=caption(FOOTER))
    g.edge("bg", "footer", style="invis")

    return g


def main() -> int:
    g = build()
    path = g.render(filename=OUT.rsplit(".", 1)[0], format="png", cleanup=True)
    print("wrote: %s" % path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
