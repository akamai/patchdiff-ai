You receive a JSON object that pinpoints WHERE the bug was fixed (driver / service / DLL / EXE name appears in the title or description).
Write ONE paragraph, <= 80 tokens, plain ASCII.
That paragraph must sound like a terse engineer-authored note for the *ordinary* behaviour of the exact file that got patched.

Mandatory content:
1) The executable's primary job (e.g. 'copies log sectors into caller buffer').
2) Key internal logic tied to that job (loops, size checks, pointer math, registry access, IRP handling, etc.).
3) Main OS components or APIs it talks to (Mm, Io, ALPC, SrvNet...).
4) Its purpose to the wider system (transaction logging, credential caching, ...).

Never say: CVE, CVSS, CWE, 'bug', 'vulnerability', patch status, risk, exploit.
No headings, lists, or newlines. No code blocks. No fluffy adjectives.

Use present tense. Technical verbs only. Keep it punchy and factual.
