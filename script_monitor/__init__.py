"""Third-Party Script Monitor.

A defensive, read-only tool that inventories the third-party <script> and
<link> resources a web page loads, hashes them, checks Subresource Integrity
(SRI), analyses the Content Security Policy (CSP) and reports changes against
a saved baseline.

It never executes JavaScript. It only downloads files as text and compares them.
"""

__version__ = "1.0.0"
