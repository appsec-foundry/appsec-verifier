"""Mask known credentials in an already observed page before capture (VER-016, VER-035).

Only the presentation changes: scripts stop after proof collection, text and field
values are replaced without dispatching events, and no request is needed. Unreadable
or unmaskable content keeps the image off disk; callers retain the technical proof.
"""

from __future__ import annotations

import base64

from ..limits import execution_deadline

_READ = """() => {
  const items = [], extra = [];
  let size = 0;
  const add = (node, kind, text, attr = null) => {
    size += text.length;
    if (size > 200000 || items.length >= 10000) throw new Error('capture text limit');
    items.push({node, kind, text, attr});
  };
  const walk = (root) => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (!node.parentElement?.closest('script,style,noscript')) add(node, 'text', node.nodeValue || '');
    }
    for (const el of root.querySelectorAll('*')) {
      if (el.matches('input,textarea,select')) add(el, 'value', el.value || '');
      for (const attr of ['alt', 'placeholder', 'title']) {
        if (el.hasAttribute(attr)) add(el, 'attribute', el.getAttribute(attr), attr);
      }
      for (const pseudo of ['::before', '::after']) {
        const text = getComputedStyle(el, pseudo).content || '';
        size += text.length;
        if (size > 200000) throw new Error('capture text limit');
        if (text !== 'none' && text !== 'normal') extra.push(text);
      }
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(document.documentElement);
  return {items, extra};
}"""

_APPLY = """(snapshot, replacements) => {
  for (const [index, text] of replacements) {
    const {node, kind, attr} = snapshot.items[index];
    if (kind === 'text') node.nodeValue = text;
    else if (kind === 'value') node.value = text;
    else node.setAttribute(attr, text);
  }
}"""


def mask_credentials(page, redact, *, protected=(), timeout=5000) -> tuple[bool, str | None]:
    """Return (masked, omission reason); never return a credential or save raw pixels.

    Freeze page activity before masking. DOM edits can still run mutation callbacks,
    so the final text is checked again. Evaluations still work, as in the
    existing script-disabled recorded-response renderer. The page is closed by its
    caller; script execution is never restored on this presentation-only page.
    """
    if redact is None:
        return False, "the screenshot text could not be checked for credentials"
    try:
        if any(redact(text) != text for text in protected):
            return False, "masking credentials would obscure the decisive observation"
        session = page.context.new_cdp_session(page)
        session.send("Emulation.setScriptExecutionDisabled", {"value": True})
        session.send("Page.setWebLifecycleState", {"state": "frozen"})
        snapshot = page.wait_for_function(_READ, timeout=timeout)
        original = snapshot.evaluate("s => s.items.map(i => i.text)")
        clean = redact(original)
        if not (isinstance(clean, list) and len(clean) == len(original)
                and all(isinstance(t, str) for t in clean)):
            return False, "the screenshot text could not be checked for credentials"
        replacements = [[i, text] for i, text in enumerate(clean) if text != original[i]]
        if replacements:
            snapshot.evaluate(_APPLY, replacements)
        snapshot.dispose()
        checked = page.wait_for_function(_READ, timeout=timeout)
        remaining = checked.evaluate("s => s.items.map(i => i.text).concat(s.extra)")
        checked.dispose()
        if redact(remaining) != remaining:
            return False, "a credential could not be masked in the screenshot text"
        return bool(replacements), None
    except Exception:  # noqa: BLE001 - keep the proof but omit an image whose masking cannot be verified
        return False, "the screenshot text could not be safely masked and checked"


def capture_masked(page, redact, *, timeout=5000, clip=None) -> tuple[bytes, str]:
    """Recheck after annotations and capture the viewport without further DOM changes.

    The native capture avoids running page-side screenshot preparation after the last
    credential check. The earlier script switch remains active; no target requests or
    file writes are performed here. A failed check leaves persistence to the caller.
    """
    with execution_deadline(timeout / 1000, kind="time"):
        checked = page.wait_for_function(_READ, timeout=timeout)
        text = checked.evaluate("s => s.items.map(i => i.text).concat(s.extra, document.body?.innerText || '')")
        checked.dispose()
        if redact is None or redact(text) != text:
            raise ValueError("the final screenshot text could not be cleared of credentials")
        session = page.context.new_cdp_session(page)
        result = session.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False,
                              **({"clip": {**clip, "scale": 1}} if clip else {})})
        return base64.b64decode(result["data"], validate=True), "\n".join(text)
