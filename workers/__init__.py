"""Background scan execution.

Milestone 6. Bounded concurrency and progress tracking so a long scan
never blocks the bot's event loop (the legacy ``/scan`` handler called
``subprocess.run`` directly inside the coroutine).
"""

from __future__ import annotations
