"""Quick asks: the ``browser`` op ``ask``, answered by the person on the live card.

The agent asks the person for one thing it must never handle itself -- a
sign-in, one short text field, a one-time code, a "not a robot" check, or the
click that buys something -- and gets back ONE non-secret outcome word.

The invariant everything here serves: a value the person types reaches only the
element the ask was bound to, on the origin it was bound to, and nothing the
agent can read ever contains it. So:

* The ask is BOUND when it is made: the page's committed top frame (id, loader,
  origin from the frame URL) and each target's ``backendNodeId``. A target in
  another document, hidden, covered or of the wrong type is refused right away.
* Every DOM read runs in an isolated world (``Page.createIsolatedWorld``), so a
  page script cannot patch ``getBoundingClientRect`` or ``elementFromPoint`` to
  fake a check. The ref -> node lookup is the only main-world read, and what it
  returns is checked in the isolated world like any other node.
* The answer is RE-CHECKED before anything is written: same frame, same
  document, same origin, every bound node still attached, visible, uncovered and
  of its type. Anything else is ``origin_changed`` and nothing is written.
* A fill is ``DOM.focus`` on the bound node, then one call on that node that
  proves it holds focus and inserts the text, in the gateway. Values are never
  logged, stored, published or put in an exception.

Pure validation (:func:`parse_ask`) and the CDP half (:class:`PageProbe`,
:func:`bind_ask`, :func:`verify`, :func:`fill`, :func:`click_once`,
:func:`human_check_passed`) live together so the contract reads in one place.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from kiro_crew.browser_harness.budgets import ASK_TIMEOUT_S, HUMAN_CHECK_TIMEOUT_S

#: The target roles each kind takes, and which of them are required.
ROLES: dict[str, tuple[tuple[str, bool], ...]] = {
    "credentials": (("username", False), ("password", True)),
    "text": (("text", True),),
    "otp": (("otp", True),),
    "human_check": (("widget", True),),
    "confirm": (("action", True),),
}
TEXT_LABELS = frozenset({"name", "email", "username", "phone", "other"})
#: The answer actions each kind accepts ("cancel" and "decline" fit every kind).
ACTIONS: dict[str, frozenset[str]] = {
    # take_over/done: only the sign-in takeover (credentials with no targets).
    "credentials": frozenset({"fill", "take_over", "done", "decline", "cancel"}),
    "text": frozenset({"fill", "decline", "cancel"}),
    "otp": frozenset({"fill", "decline", "cancel"}),
    "human_check": frozenset({"take_over", "done", "decline", "cancel"}),
    "confirm": frozenset({"confirm", "decline", "cancel"}),
}

FILLED = "filled"
DECLINED = "declined"
PASSED = "passed"
CONFIRMED = "confirmed"
CANCELLED = "cancelled"
ORIGIN_CHANGED = "origin_changed"
TIMED_OUT = "timed_out"
REFUSED = "refused"

REASON_MAX = 80
SUMMARY_MAX = 120
BUTTON_TEXT_MAX = 60
#: The largest human_check widget, in CSS pixels: a challenge pane (reCAPTCHA's is
#: about 400 x 580), never a whole page.
WIDGET_MAX_W = 520
WIDGET_MAX_H = 720
OTP_DIGITS_MIN = 4
OTP_DIGITS_MAX = 10
#: The answer route's caps.
ANSWER_BODY_MAX = 8 * 1024
VALUE_MAX = 1024

PHASE_WAITING = "waiting"
PHASE_TAKEN_OVER = "taken_over"

#: ``eN``, or ``f<tag>eN`` for an element inside a cross-origin frame (``frames.py``).
_REF_RE = re.compile(r"^(?:f[1-9][0-9]{0,3})?e[1-9][0-9]{0,6}$")
#: An iframe a quick ask writes through must be at least this opaque (the product
#: of its own and its ancestors' opacity): a see-through frame over a decoy is the
#: clickjacking shape, where the person thinks they type into what they see.
FRAME_OPACITY_MIN = 0.5
#: C0/C1 controls, and the zero-width and bidi-override characters that let a
#: reason read differently from what it says.
_UNSAFE_RE = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_SPACE_RE = re.compile(r"\s+")
#: Editable text input types for ``text``/``otp``/``username`` targets.
_TEXT_TYPES = frozenset({"", "text", "email", "tel", "number", "search", "url"})


class AskError(Exception):
    """An ask refused, or an answer that could not land. ``code`` is the whole message:
    no page text and no value ever rides on it."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def clean_text(raw: Any, limit: int) -> str:
    """Plain one-line text: unsafe characters dropped, whitespace folded, cut to *limit*."""
    if not isinstance(raw, str):
        return ""
    # Whitespace (newlines and tabs included) folds to a space first, so dropping
    # the unsafe characters after it never glues two words together.
    text = _SPACE_RE.sub(" ", _UNSAFE_RE.sub("", _SPACE_RE.sub(" ", raw))).strip()
    return text[:limit].rstrip()


@dataclass(frozen=True)
class AskSpec:
    kind: str
    targets: dict[str, str]
    reason: str
    label: str = ""
    digits: int = 0
    summary: str = ""

    @property
    def sign_in_takeover(self) -> bool:
        """Credentials with no targets: the person signs in on the page itself."""
        return self.kind == "credentials" and not self.targets

    @property
    def takes_over(self) -> bool:
        """The answer is the person's own hands on the page, not a value we write."""
        return self.kind == "human_check" or self.sign_in_takeover


def _targets(raw: Any, kind: str) -> dict[str, str]:
    """``targets``: a list of ``"role=ref"`` strings (the tool's args are flat), or an object.

    ``credentials`` with none at all is the sign-in takeover: the snapshot had no
    ref for the fields (a frame it could not read), so the person signs in on the
    page themselves instead of through the sheet.
    """
    if kind == "credentials" and raw in (None, [], {}):
        return {}
    pairs: list[tuple[str, Any]] = []
    if isinstance(raw, dict):
        pairs = list(raw.items())
    elif isinstance(raw, list):
        for item in raw:
            if not isinstance(item, str) or "=" not in item:
                raise AskError("bad_targets")
            role, _, ref = item.partition("=")
            pairs.append((role.strip(), ref.strip()))
    else:
        raise AskError("bad_targets")
    allowed = dict(ROLES[kind])
    out: dict[str, str] = {}
    for role, ref in pairs:
        if role not in allowed or role in out:
            raise AskError("bad_targets")
        if not isinstance(ref, str) or not _REF_RE.match(ref):
            raise AskError("bad_ref")
        out[role] = ref
    for role, required in ROLES[kind]:
        if required and role not in out:
            raise AskError("bad_targets")
    if len(set(out.values())) != len(out):
        raise AskError("bad_targets")
    return out


def parse_ask(args: Any) -> AskSpec:
    """Validate the agent's ``ask`` args. Raises :class:`AskError` (``bad_*``)."""
    if not isinstance(args, dict):
        raise AskError("bad_args")
    kind = args.get("kind")
    if kind not in ROLES:
        raise AskError("bad_kind")
    targets = _targets(args.get("targets"), kind)
    reason = clean_text(args.get("reason"), REASON_MAX)
    if not reason:
        raise AskError("bad_reason")
    label = ""
    digits = 0
    summary = ""
    if kind == "text":
        raw_label = args.get("label")
        label = raw_label if isinstance(raw_label, str) and raw_label in TEXT_LABELS else "other"
    if kind == "otp":
        raw_digits = args.get("digits")
        if isinstance(raw_digits, bool) or not isinstance(raw_digits, int):
            raise AskError("bad_digits")
        if not OTP_DIGITS_MIN <= raw_digits <= OTP_DIGITS_MAX:
            raise AskError("bad_digits")
        digits = raw_digits
    if kind == "confirm":
        summary = clean_text(args.get("summary"), SUMMARY_MAX)
        if not summary:
            raise AskError("bad_summary")
    return AskSpec(kind, targets, reason, label=label, digits=digits, summary=summary)


def origin_of(url: str) -> str:
    """``scheme://host[:port]`` of an http(s) URL, else ``""``."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        return ""
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{host}" + (f":{port}" if port and port != default else "")


@dataclass
class Binding:
    role: str
    node: int
    #: The target's rect in viewport CSS pixels at ask time.
    rect: tuple[float, float, float, float]
    input: str = ""


@dataclass
class QuickAsk:
    """One pending ask: what it was bound to, what the card shows, and how it ended.

    ``origin``, ``frame_id`` and ``loader_id`` are the frame the targets live in:
    the top frame, or an iframe. ``top_*`` are the tab's top frame. For an iframe,
    ``owner`` is its ``<iframe>`` element in the top document and ``frame_session``
    the CDP session its isolated world and writes go through (the stream's own,
    or the frame's child session when it runs out of process). Binding rects are
    the frame's own viewport pixels; ``offset`` moves them into the page's.
    """

    spec: AskSpec
    origin: str
    frame_id: str
    loader_id: str
    bindings: list[Binding]
    scale: float
    frame_w: int
    frame_h: int
    button: str = ""
    top_origin: str = ""
    top_frame_id: str = ""
    top_loader_id: str = ""
    owner: int = 0
    frame_session: str = ""
    offset: tuple[float, float] = (0.0, 0.0)
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    expires_at: int = 0
    deadline: float = 0.0
    phase: str = PHASE_WAITING
    outcome: str = ""
    #: Set once the ask has an outcome; the agent's poll waits on it.
    settled: asyncio.Event = field(default_factory=asyncio.Event)
    #: The scoped takeover this ask claimed (human_check): input outside this
    #: frame-pixel rect is dropped while it is held.
    claimed: bool = False
    #: The tab (CDP target) the card streamed when the ask was bound.
    target_id: str = ""
    #: One answer at a time: a double-clicked Fill runs once.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        # A top-frame ask: the asked frame IS the top frame.
        if not self.top_frame_id:
            self.top_frame_id, self.top_loader_id = self.frame_id, self.loader_id
            self.top_origin = self.top_origin or self.origin

    def start_clock(self, now_mono: float) -> None:
        span = HUMAN_CHECK_TIMEOUT_S if self.spec.takes_over else ASK_TIMEOUT_S
        self.deadline = now_mono + span
        self.expires_at = int((time.time() + span) * 1000)

    def settle(self, outcome: str) -> bool:
        if self.outcome:
            return False
        self.outcome = outcome
        self.settled.set()
        return True

    def wire(self) -> dict[str, Any]:
        """The card's ``ask`` field. Built from bound state only, never page text but the button."""
        fields = []
        ox, oy = self.offset
        for b in self.bindings:
            bx, by, bw, bh = b.rect
            x, y, w, h = _frame_rect((bx + ox, by + oy, bw, bh), self.scale)
            entry: dict[str, Any] = {"role": b.role, "rect": {"x": x, "y": y, "w": w, "h": h}}
            if b.input:
                entry["input"] = b.input
            if b.role == "text":
                entry["label"] = self.spec.label
            fields.append(entry)
        out: dict[str, Any] = {
            "id": self.id,
            "kind": self.spec.kind,
            "origin": self.origin,
            "reason": self.spec.reason,
            "fields": fields,
            "frame": {"w": self.frame_w, "h": self.frame_h},
            "expires_at": self.expires_at,
            "phase": self.phase,
        }
        if self.top_origin and self.top_origin != self.origin:
            # Shown as "<origin> (inside <top_origin>)": both from the browser.
            out["top_origin"] = self.top_origin
        if self.spec.kind == "otp":
            out["digits"] = self.spec.digits
        if self.spec.kind == "confirm":
            out["summary"] = self.spec.summary
            out["button"] = self.button
        return out


def _frame_rect(rect: tuple[float, float, float, float], scale: float) -> tuple[int, int, int, int]:
    s = scale if scale > 0 else 1.0
    x, y, w, h = rect
    return int(round(x * s)), int(round(y * s)), int(round(w * s)), int(round(h * s))


# -- the CDP half -------------------------------------------------------------

#: Runs ON the target element in the isolated world. Reads only; the page's own
#: prototypes are not reachable from here, so it cannot be lied to.
_INSPECT_JS = """function () {
  var el = this, d = document;
  var root = el.getRootNode ? el.getRootNode() : d;
  var r = el.getBoundingClientRect();
  var cs = getComputedStyle(el);
  var op = parseFloat(cs.opacity || '1');
  var visible = r.width >= 2 && r.height >= 2 && cs.display !== 'none'
    && cs.visibility !== 'hidden' && op > 0.05;
  for (var p = el.parentElement; visible && p; p = p.parentElement) {
    var ps = getComputedStyle(p);
    op *= parseFloat(ps.opacity || '1');
    if (ps.display === 'none' || ps.visibility === 'hidden'
        || parseFloat(ps.opacity || '1') <= 0.05) visible = false;
  }
  var cx = r.left + r.width / 2, cy = r.top + r.height / 2;
  var inView = cx >= 0 && cy >= 0 && cx < innerWidth && cy < innerHeight;
  var hitRoot = root && root.elementFromPoint ? root : d;
  var hit = inView ? hitRoot.elementFromPoint(cx, cy) : null;
  var tag = (el.tagName || '').toLowerCase();
  var text = '';
  if (tag === 'input') text = el.value || ''; else text = el.innerText || el.textContent || '';
  return {
    connected: el.isConnected === true,
    sameDoc: el.ownerDocument === d,
    tag: tag,
    type: tag === 'input' ? String(el.type || '').toLowerCase() : '',
    role: String(el.getAttribute('role') || '').toLowerCase(),
    href: tag === 'a' && el.hasAttribute('href'),
    disabled: el.disabled === true || el.getAttribute('aria-disabled') === 'true',
    readOnly: el.readOnly === true,
    visible: visible,
    covered: !(hit && (hit === el || el.contains(hit))),
    rect: [r.left, r.top, r.width, r.height],
    op: op,
    vw: innerWidth, vh: innerHeight,
    text: text.replace(/\\s+/g, ' ').trim().slice(0, 120)
  };
}"""

#: Insert *v* into the bound element, only if it holds focus (through open shadow
#: roots). The check and the insert run in one synchronous call on the element,
#: so no page script runs between them and the text cannot land anywhere else.
_INSERT_JS = """function (v) {
  var root = this.getRootNode ? this.getRootNode() : document;
  if (root.activeElement !== this) return false;
  return document.execCommand('insertText', false, v) === true;
}"""

#: Mark the field as the person's (the snapshot walker, the frame mask and the
#: screenshot guard then withhold its value) and put the caret over its whole
#: value so the insert replaces it.
_PREPARE_JS = """function () {
  this.setAttribute('data-kc-asked', '');
  try { if (typeof this.select === 'function') this.select(); } catch (e) {}
  return true;
}"""

#: Has the human_check widget reported success? A checkbox-style widget sets
#: aria-checked; the token widgets write a non-empty response field into the page.
_PASSED_JS = """function () {
  var el = this;
  if (el.getAttribute('aria-checked') === 'true' || el.checked === true) return true;
  if (el.querySelector && el.querySelector('[aria-checked="true"]')) return true;
  var names = ['g-recaptcha-response', 'h-captcha-response', 'cf-turnstile-response'];
  for (var i = 0; i < names.length; i++) {
    var f = document.querySelectorAll('[name="' + names[i] + '"]');
    for (var j = 0; j < f.length; j++) if (f[j].value) return true;
  }
  return false;
}"""

#: Is the topmost element at (x, y) of the top document this ``<iframe>``? Runs on
#: the frame's owner in the TOP frame's isolated world: a decoy laid over the frame
#: (or the frame slid away under the field's point) answers no.
_HIT_JS = """function (x, y) {
  if (!(x >= 0 && y >= 0 && x < innerWidth && y < innerHeight)) return false;
  return document.elementFromPoint(x, y) === this;
}"""

#: The sign-in takeover's zoom box: the largest visible form or iframe holding a
#: password box or a login-looking frame, clipped to the viewport; else the
#: largest visible form or iframe. Run in the isolated world: page script cannot
#: move it. ``null`` when there is none (the card then does not zoom).
_REGION_JS = """(() => {
  var best = null, area = 0;
  var all = document.querySelectorAll('form, iframe');
  for (var i = 0; i < all.length; i++) {
    var el = all[i], r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    var x = Math.max(0, r.left), y = Math.max(0, r.top);
    var w = Math.min(innerWidth, r.right) - x, h = Math.min(innerHeight, r.bottom) - y;
    if (w < 40 || h < 40) continue;
    var a = w * h;
    if (el.tagName === 'FORM' && el.querySelector('input[type=password]')) a *= 4;
    if (a > area) { area = a; best = [x, y, w, h]; }
  }
  return { region: best, vw: innerWidth, vh: innerHeight };
})()"""

_WORLD = "kirocrew_quick_ask"


class PageProbe:
    """The CDP calls an ask makes, on the live stream's own session for the tab."""

    def __init__(self, relay: Any, session_id: str) -> None:
        self.relay = relay
        self.session_id = session_id

    async def _send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        try:
            reply = await self.relay.send(method, params, self.session_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            # The method name only: a CDP error never carries a value through here.
            raise AskError("cdp_failed") from None
        return reply if isinstance(reply, dict) else {}

    async def top_frame(self) -> tuple[str, str, str]:
        """``(frame_id, loader_id, origin)`` of the committed top frame."""
        tree = await self._send("Page.getFrameTree", {})
        frame = (tree.get("frameTree") or {}).get("frame") or {}
        return (
            str(frame.get("id") or ""),
            str(frame.get("loaderId") or ""),
            origin_of(str(frame.get("url") or "")),
        )

    async def frame(self, frame_id: str) -> tuple[str, str, str]:
        """``(frame_id, loader_id, origin)`` of one frame this session's tree holds."""
        tree = await self._send("Page.getFrameTree", {})
        todo = [tree.get("frameTree") or {}]
        while todo:
            node = todo.pop()
            frame = node.get("frame") or {}
            if frame.get("id") == frame_id:
                return (
                    str(frame.get("id") or ""),
                    str(frame.get("loaderId") or ""),
                    origin_of(str(frame.get("url") or "")),
                )
            todo.extend(node.get("childFrames") or [])
        return ("", "", "")

    async def ref_frame(self, ref: str) -> str:
        """The frame id of the document a top-map ref lives in, ``""`` for this one.

        A main-world read (which frame to look in), never trusted on its own: the
        node is then resolved INTO that frame's isolated world and must be found
        in that frame's own document there, or the ask is refused.
        """
        expr = (
            "(() => { var m = window.__kcRefDocObj === document && window.__kcRefs instanceof Map"
            f" ? window.__kcRefs.get({ref!r}) : null; if (!m || m.ownerDocument === document)"
            " return null; try { return m.ownerDocument.defaultView.frameElement; }"
            " catch (e) { return null; } })()"
        )
        found = await self._send("Runtime.evaluate", {"expression": expr, "returnByValue": False})
        obj = (found.get("result") or {}).get("objectId")
        if not obj:
            return ""
        try:
            desc = await self._send("DOM.describeNode", {"objectId": obj})
        finally:
            try:
                await self._send("Runtime.releaseObject", {"objectId": obj})
            except AskError:
                pass
        frame_id = (desc.get("node") or {}).get("frameId")
        if not isinstance(frame_id, str) or not frame_id:
            raise AskError("cross_frame")
        return frame_id

    async def frame_owner(self, frame_id: str) -> int:
        """The ``backendNodeId`` of the ``<iframe>`` that holds *frame_id*, from the browser."""
        owner = await self._send("DOM.getFrameOwner", {"frameId": frame_id})
        node = owner.get("backendNodeId")
        if not isinstance(node, int):
            raise AskError("frame_unverified")
        return node

    async def content_origin(self, node: int, frame_width: float) -> tuple[float, float]:
        """Where the frame's viewport starts in the page, measured by the browser.

        Refused (``frame_transformed``) when the frame is rotated or scaled: its
        pixels would not be the page's, and no check made in one maps onto the other.
        """
        from kiro_crew.browser_harness.frames import content_origin

        model = (await self._send("DOM.getBoxModel", {"backendNodeId": node})).get("model") or {}
        at = content_origin(model.get("content"), frame_width)
        if at is None:
            raise AskError("frame_transformed")
        return at

    async def evaluate(self, ctx: int, expression: str) -> Any:
        out = await self._send(
            "Runtime.evaluate",
            {"expression": expression, "contextId": ctx, "returnByValue": True},
        )
        if out.get("exceptionDetails"):
            raise AskError("cdp_failed")
        return (out.get("result") or {}).get("value")

    async def world(self, frame_id: str) -> int:
        made = await self._send(
            "Page.createIsolatedWorld",
            {"frameId": frame_id, "worldName": _WORLD, "grantUniveralAccess": False},
        )
        ctx = made.get("executionContextId")
        if not isinstance(ctx, int):
            raise AskError("cdp_failed")
        return ctx

    async def ref_node(self, ref: str) -> int:
        """The ``backendNodeId`` a snapshot ref names, or :class:`AskError` ``ref_stale``."""
        expr = (
            "(window.__kcRefDocObj === document && window.__kcRefs instanceof Map)"
            f" ? (window.__kcRefs.get({ref!r}) || null) : null"
        )
        found = await self._send("Runtime.evaluate", {"expression": expr, "returnByValue": False})
        obj = (found.get("result") or {}).get("objectId")
        if not obj:
            raise AskError("ref_stale")
        try:
            desc = await self._send("DOM.describeNode", {"objectId": obj})
        finally:
            try:
                await self._send("Runtime.releaseObject", {"objectId": obj})
            except AskError:
                pass
        node = (desc.get("node") or {}).get("backendNodeId")
        if not isinstance(node, int):
            raise AskError("ref_stale")
        return node

    async def call(self, node: int, ctx: int, js: str, *args: Any) -> Any:
        """Run *js* on *node* in the isolated world *ctx*; its by-value result.

        *args* ride as call arguments. A failure says only ``cdp_failed``: the
        exception details (which could echo an argument) are never read.
        """
        resolved = await self._send(
            "DOM.resolveNode", {"backendNodeId": node, "executionContextId": ctx}
        )
        obj = (resolved.get("object") or {}).get("objectId")
        if not obj:
            raise AskError("gone")
        try:
            out = await self._send(
                "Runtime.callFunctionOn",
                {
                    "objectId": obj,
                    "functionDeclaration": js,
                    "returnByValue": True,
                    **({"arguments": [{"value": a} for a in args]} if args else {}),
                },
            )
        finally:
            try:
                await self._send("Runtime.releaseObject", {"objectId": obj})
            except AskError:
                pass
        if out.get("exceptionDetails"):
            raise AskError("cdp_failed")
        return (out.get("result") or {}).get("value")

    async def inspect(self, node: int, ctx: int) -> dict[str, Any]:
        info = await self.call(node, ctx, _INSPECT_JS)
        if not isinstance(info, dict):
            raise AskError("cdp_failed")
        return info


def target_problem(role: str, info: dict[str, Any]) -> str:
    """Why this element cannot take this role, or ``""``. The refusal codes."""
    if not info.get("connected"):
        return "gone"
    if not info.get("sameDoc"):
        return "cross_frame"
    if not info.get("visible"):
        return "hidden"
    if info.get("covered"):
        return "covered"
    tag, typ = info.get("tag"), info.get("type")
    if role == "password":
        if tag != "input" or typ != "password":
            return "wrong_type"
    elif role in ("username", "text", "otp"):
        if tag != "input" or typ not in _TEXT_TYPES:
            return "wrong_type"
    elif role == "widget":
        # A CAPTCHA frame or a checkbox, no bigger than a challenge pane: never a
        # button or a page-sized box the person's "tick" would land on.
        boxy = (
            tag == "iframe"
            or (tag == "input" and typ == "checkbox")
            or info.get("role") == "checkbox"
        )
        if not boxy:
            return "wrong_type"
        rect = info.get("rect") or [0, 0, 0, 0]
        if float(rect[2]) > WIDGET_MAX_W or float(rect[3]) > WIDGET_MAX_H:
            return "too_large"
    elif role == "action":
        clickable = (
            tag == "button"
            or (tag == "input" and typ in ("submit", "button"))
            or (tag == "a" and info.get("href"))
            or info.get("role") == "button"
        )
        if not clickable:
            return "wrong_type"
    if role != "widget" and (info.get("disabled") or info.get("readOnly")):
        return "disabled"
    return ""


_INPUT_KIND = {"username": "text", "password": "password", "otp": "otp"}


def owner_problem(info: dict[str, Any]) -> str:
    """Why the ``<iframe>`` holding the targets cannot carry an ask, or ``""``.

    It must sit in the top document itself (a frame in a frame is refused: its
    position is the inner page's to fake), be shown at a real size (at least
    2 x 2, never ``display: none`` or ``visibility: hidden``) and be close to
    opaque: a see-through frame over a decoy is the clickjacking shape.
    """
    if not info.get("connected"):
        return "gone"
    if not info.get("sameDoc"):
        return "nested_frame"
    if info.get("tag") not in ("iframe", "frame"):
        return "frame_unverified"
    if not info.get("visible"):
        return "hidden"
    try:
        opacity = float(info.get("op", 1.0))
    except (TypeError, ValueError):
        opacity = 0.0
    if opacity < FRAME_OPACITY_MIN:
        return "transparent"
    return ""


async def _locate(top: PageProbe, frames: Any, ref: str) -> tuple[PageProbe, int, str]:
    """``(probe, backendNodeId, frame_id)`` for one target ref; ``frame_id`` ``""`` = top.

    ``f<tag>eN`` names an element of a cross-origin frame: its probe is that
    frame's child session. ``eN`` is in the top map: the top document's, or a
    same-origin frame's, on the stream's own session.
    """
    from kiro_crew.browser_harness.frames import split_frame_ref

    framed = split_frame_ref(ref)
    if framed is not None:
        tag, local = framed
        frame_id = frames.frame_of(tag) if frames is not None else ""
        sid = frames.session_of(frame_id) if frame_id else ""
        if not sid:
            raise AskError("ref_stale")
        probe = PageProbe(top.relay, sid)
        return probe, await probe.ref_node(local), frame_id
    node = await top.ref_node(ref)
    return top, node, await top.ref_frame(ref)


async def _frame_identity(top: PageProbe, fprobe: PageProbe, frame_id: str) -> tuple[str, str, str]:
    """``(frame_id, loader_id, origin)`` of the frame as its own session commits it."""
    if fprobe.session_id == top.session_id:
        return await top.frame(frame_id)
    return await fprobe.top_frame()


async def _check_frame(
    top: PageProbe,
    top_ctx: int,
    owner: int,
    rects: list[tuple[float, float, float, float]],
    frame_width: float,
) -> tuple[tuple[float, float], float, float]:
    """The frame's offset in the page and the page's viewport, once the frame passes.

    The frame's own checks (hidden, covered INSIDE it) ran on the targets in the
    frame's world. Here, in the top frame's world: the owner is fit to carry an
    ask (:func:`owner_problem`), it is placed exactly (no scale, no rotation),
    and at each target's centre, mapped to page pixels, the top document's
    topmost element is the owner itself, so nothing is laid over the field.
    """
    info = await top.inspect(owner, top_ctx)
    problem = owner_problem(info)
    if problem:
        raise AskError(problem)
    at = await top.content_origin(owner, frame_width)
    for x, y, w, h in rects:
        px, py = round(at[0] + x + w / 2, 2), round(at[1] + y + h / 2, 2)
        if await top.call(owner, top_ctx, _HIT_JS, px, py) is not True:
            raise AskError("covered")
    return at, float(info.get("vw") or 0), float(info.get("vh") or 0)


async def bind_ask(probe: PageProbe, spec: AskSpec, scale: float, frames: Any = None) -> QuickAsk:
    """Bind *spec* to the page as it is now. Raises :class:`AskError` with the refusal code.

    *probe* is the stream's session on the tab; *frames* its
    ``browser_harness.frames.FrameRegistry`` (the cross-origin frames' sessions).
    Every target must live in ONE frame; the ask is bound to that frame's
    committed origin, its id and loader, its owner element, and the top frame's.
    """
    top = probe
    top_id, top_loader, top_origin = await top.top_frame()
    if not top_id or not top_origin:
        raise AskError("not_web_page")
    top_ctx = await top.world(top_id)
    s = scale if scale > 0 else 1.0
    if spec.sign_in_takeover:
        return await _bind_sign_in(top, spec, s, top_id, top_loader, top_origin, top_ctx)
    order = [role for role, _ in ROLES[spec.kind] if role in spec.targets]
    located = [(role, *await _locate(top, frames, spec.targets[role])) for role in order]
    frame_id = located[0][3] or top_id
    fprobe = located[0][1]
    if any(
        (f or top_id) != frame_id or p.session_id != fprobe.session_id for _, p, _, f in located
    ):
        raise AskError("cross_frame")
    if frame_id == top_id:
        loader_id, origin, ctx = top_loader, top_origin, top_ctx
    else:
        fid, loader_id, origin = await _frame_identity(top, fprobe, frame_id)
        if fid != frame_id or not loader_id:
            raise AskError("frame_unverified")
        if not origin:
            raise AskError("not_web_page")
        ctx = await fprobe.world(frame_id)
    bindings: list[Binding] = []
    button = ""
    vw = vh = 0.0
    for role, _p, node, _f in located:
        info = await fprobe.inspect(node, ctx)
        problem = target_problem(role, info)
        if problem:
            raise AskError(problem)
        x, y, w, h = (float(v) for v in info["rect"])
        typ = str(info.get("type") or "text")
        kind = _INPUT_KIND.get(role, "")
        if role == "text":
            kind = typ if typ in ("email", "tel") else "text"
        bindings.append(Binding(role=role, node=node, rect=(x, y, w, h), input=kind))
        if role == "action":
            button = clean_text(info.get("text"), BUTTON_TEXT_MAX)
            if not button:
                raise AskError("no_button_text")
        vw, vh = float(info.get("vw") or 0), float(info.get("vh") or 0)
    owner = 0
    offset = (0.0, 0.0)
    if frame_id != top_id:
        owner = await top.frame_owner(frame_id)
        offset, vw, vh = await _check_frame(top, top_ctx, owner, [b.rect for b in bindings], vw)
    return QuickAsk(
        spec=spec,
        origin=origin,
        frame_id=frame_id,
        loader_id=loader_id,
        bindings=bindings,
        scale=s,
        frame_w=int(round(vw * s)),
        frame_h=int(round(vh * s)),
        button=button,
        top_origin=top_origin,
        top_frame_id=top_id,
        top_loader_id=top_loader,
        owner=owner,
        frame_session=fprobe.session_id,
        offset=offset,
    )


async def _bind_sign_in(
    top: PageProbe,
    spec: AskSpec,
    scale: float,
    top_id: str,
    top_loader: str,
    top_origin: str,
    top_ctx: int,
) -> QuickAsk:
    """The sign-in takeover: no field is bound, only the page and the box to zoom on."""
    found = await top.evaluate(top_ctx, _REGION_JS)
    if not isinstance(found, dict):
        raise AskError("cdp_failed")
    vw, vh = float(found.get("vw") or 0), float(found.get("vh") or 0)
    region = found.get("region")
    rect = (
        tuple(float(v) for v in region)
        if isinstance(region, list) and len(region) == 4
        else (0.0, 0.0, vw, vh)
    )
    return QuickAsk(
        spec=spec,
        origin=top_origin,
        frame_id=top_id,
        loader_id=top_loader,
        bindings=[Binding(role="region", node=0, rect=rect)],  # type: ignore[arg-type]
        scale=scale,
        frame_w=int(round(vw * scale)),
        frame_h=int(round(vh * scale)),
        top_origin=top_origin,
        top_frame_id=top_id,
        top_loader_id=top_loader,
        frame_session=top.session_id,
    )


def _frame_probe(top: PageProbe, ask: QuickAsk) -> PageProbe:
    if not ask.frame_session or ask.frame_session == top.session_id:
        return top
    return PageProbe(top.relay, ask.frame_session)


async def _recheck(top: PageProbe, ask: QuickAsk) -> tuple[PageProbe, int, list[dict[str, Any]]]:
    """Every check :func:`bind_ask` made, made again now. ``origin_changed`` on any miss.

    Same top frame (id, loader, origin); for an iframe, the same frame (id,
    loader, origin) in the same owner element, still fit and uncovered at each
    target; every bound node still attached, visible, uncovered and of its type.
    Answers the frame's probe, its isolated world and each target's fresh read.
    """
    try:
        if await top.top_frame() != (ask.top_frame_id, ask.top_loader_id, ask.top_origin):
            raise AskError(ORIGIN_CHANGED)
        fprobe = _frame_probe(top, ask)
        top_ctx = await top.world(ask.top_frame_id)
        ctx = top_ctx
        if ask.owner:
            identity = await _frame_identity(top, fprobe, ask.frame_id)
            if identity != (ask.frame_id, ask.loader_id, ask.origin):
                raise AskError(ORIGIN_CHANGED)
            if await top.frame_owner(ask.frame_id) != ask.owner:
                raise AskError(ORIGIN_CHANGED)
            ctx = await fprobe.world(ask.frame_id)
        infos: list[dict[str, Any]] = []
        for b in ask.bindings:
            if not b.node:
                continue  # the sign-in takeover binds no element
            info = await fprobe.inspect(b.node, ctx)
            if target_problem(b.role, info):
                raise AskError(ORIGIN_CHANGED)
            infos.append(info)
        if ask.owner:
            rects = [tuple(float(v) for v in i["rect"]) for i in infos]
            width = float(infos[0].get("vw") or 0) if infos else 0.0
            ask.offset, _vw, _vh = await _check_frame(top, top_ctx, ask.owner, rects, width)  # type: ignore[arg-type]
    except AskError as exc:
        raise AskError(ORIGIN_CHANGED) from exc.__cause__
    return fprobe, ctx, infos


async def verify(probe: PageProbe, ask: QuickAsk) -> int:
    """Re-check the binding; the target frame's isolated world, or ``origin_changed``."""
    _fprobe, ctx, _infos = await _recheck(probe, ask)
    return ctx


async def fill(probe: PageProbe, ask: QuickAsk, values: dict[str, str]) -> None:
    """Write each value into its own bound node. Raises ``origin_changed``.

    Re-verified first; then, per field, focus the bound node, select its contents,
    and insert the text in ONE call on that node that first proves it holds focus
    (:data:`_INSERT_JS`). For an iframe all three go through the frame's own
    session and isolated world. The values never leave this function except as
    that call's argument. A page that moves on after the last insert (an OTP box
    that submits itself) still counts as filled: everything landed where it was bound.
    """
    fprobe, ctx, _infos = await _recheck(probe, ask)
    for b in ask.bindings:
        value = values.get(b.role)
        if value is None:
            continue
        await fprobe._send("DOM.focus", {"backendNodeId": b.node})
        await fprobe.call(b.node, ctx, _PREPARE_JS)
        if await fprobe.call(b.node, ctx, _INSERT_JS, value) is not True:
            raise AskError(ORIGIN_CHANGED)


async def click_once(probe: PageProbe, ask: QuickAsk) -> None:
    """The confirm ask's ONE click: re-verified, at the bound button's centre right now."""
    _fprobe, _ctx, infos = await _recheck(probe, ask)
    x, y, w, h = (float(v) for v in infos[0]["rect"])
    ox, oy = ask.offset
    point = {
        "x": round(ox + x + w / 2, 2),
        "y": round(oy + y + h / 2, 2),
        "button": "left",
        "clickCount": 1,
    }
    await probe._send("Input.dispatchMouseEvent", {"type": "mousePressed", **point})
    await probe._send("Input.dispatchMouseEvent", {"type": "mouseReleased", **point})


async def takeover_rect_now(probe: PageProbe, ask: QuickAsk) -> tuple[float, float, float, float]:
    """The box the person's takeover zooms on, in page CSS pixels, measured NOW
    (re-verified): a scroll or layout shift since the ask must not move it off."""
    _fprobe, ctx, infos = await _recheck(probe, ask)
    if ask.spec.sign_in_takeover:
        found = await probe.evaluate(ctx, _REGION_JS)
        region = found.get("region") if isinstance(found, dict) else None
        if isinstance(region, list) and len(region) == 4:
            x, y, w, h = (float(v) for v in region)
            return x, y, w, h
        return ask.bindings[0].rect
    x, y, w, h = (float(v) for v in infos[0]["rect"])
    ox, oy = ask.offset
    return ox + x, oy + y, w, h


#: The old name, for the human_check widget.
widget_rect_now = takeover_rect_now


async def page_moved(probe: PageProbe, ask: QuickAsk) -> bool:
    """Whether the top frame committed another document since the ask (the sign-in
    takeover hands back on it). A read that fails counts as moved."""
    try:
        return await probe.top_frame() != (ask.top_frame_id, ask.top_loader_id, ask.top_origin)
    except AskError:
        return True


async def human_check_passed(probe: PageProbe, ask: QuickAsk) -> bool:
    """Whether the widget reports success. Raises ``origin_changed`` when the page moved."""
    if await probe.top_frame() != (ask.top_frame_id, ask.top_loader_id, ask.top_origin):
        raise AskError(ORIGIN_CHANGED)
    fprobe = _frame_probe(probe, ask)
    try:
        if ask.owner and await _frame_identity(probe, fprobe, ask.frame_id) != (
            ask.frame_id,
            ask.loader_id,
            ask.origin,
        ):
            raise AskError(ORIGIN_CHANGED)
        ctx = await fprobe.world(ask.frame_id)
        return await fprobe.call(ask.bindings[0].node, ctx, _PASSED_JS) is True
    except AskError:
        raise AskError(ORIGIN_CHANGED) from None


def check_values(ask: QuickAsk, values: Any) -> dict[str, str] | None:
    """The fill's values, shaped and bounded for this ask, or ``None`` when they do not fit."""
    if not isinstance(values, dict) or ask.spec.sign_in_takeover:
        return None
    out: dict[str, str] = {}
    for b in ask.bindings:
        name = b.role
        raw = values.get(name)
        if name == "username" and raw is None:
            # Optional on the card: the page may already hold it. Left unwritten.
            continue
        if not isinstance(raw, str) or not raw or len(raw) > VALUE_MAX:
            return None
        if name == "otp" and (
            len(raw) != ask.spec.digits or not raw.isdigit() or not raw.isascii()
        ):
            return None
        if "\n" in raw or "\r" in raw:
            return None
        out[name] = raw
    extra = set(values) - {b.role for b in ask.bindings}
    if extra:
        return None
    return out


__all__ = [
    "ACTIONS",
    "ANSWER_BODY_MAX",
    "AskError",
    "AskSpec",
    "Binding",
    "PageProbe",
    "QuickAsk",
    "VALUE_MAX",
    "bind_ask",
    "check_values",
    "clean_text",
    "click_once",
    "fill",
    "human_check_passed",
    "origin_of",
    "owner_problem",
    "page_moved",
    "takeover_rect_now",
    "parse_ask",
    "target_problem",
    "verify",
]
