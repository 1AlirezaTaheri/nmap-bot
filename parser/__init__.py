"""nmap execution and XML parsing.

Milestone 4.

- ``nmap_runner.py`` — invoke nmap with ``-oX`` and a fixed, validated
  option set (no user-supplied flags, to avoid command injection).
- ``xml_parser.py``  — read nmap's XML into typed records.
- ``normalizer.py``  — canonicalize hosts/services for storage and diffing.
"""

from __future__ import annotations
