"""Coverage for the unified error system: codes, JSON descriptions, severity,
context, and the :func:`dispatch_error` sink contract."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from protocol import errors
from protocol.errors import (
    ChatError,
    CryptoError,
    ErrorCode,
    ServerError,
    Severity,
    TransportError,
    describe,
    dispatch_error,
    format_code,
    split_code,
)


def _all_chat_error_subclasses() -> list[type]:
    seen: list[type] = [ChatError]
    stack: list[type] = [ChatError]
    while stack:
        c = stack.pop()
        for sub in c.__subclasses__():
            if sub not in seen:
                seen.append(sub)
                stack.append(sub)
    return seen


class TestCodes:
    def test_codes_unique(self) -> None:
        codes: dict[int, type] = {}
        for cls in _all_chat_error_subclasses():
            assert cls.code not in codes or codes[cls.code] is cls, (
                f"Duplicate code {format_code(cls.code)}: "
                f"{codes[cls.code].__name__} vs {cls.__name__}"
            )
            codes[cls.code] = cls

    def test_codes_within_12_bits(self) -> None:
        for cls in _all_chat_error_subclasses():
            assert 0 <= cls.code <= 0xFFF, f"{cls.__name__} code out of 12-bit range"

    def test_format_code_padded(self) -> None:
        assert format_code(0x0) == "0x000"
        assert format_code(0xABC) == "0xABC"
        assert format_code(0xFFF) == "0xFFF"

    def test_split_code_nibbles(self) -> None:
        # 0x523 = system=5, sub=2, subsub=3
        assert split_code(0x523) == (5, 2, 3)
        assert split_code(0xFFF) == (15, 15, 15)
        assert split_code(0x000) == (0, 0, 0)


class TestDescriptionsJson:
    def test_every_code_has_description(self) -> None:
        with (Path(errors.__file__).with_name("error_descriptions.json")).open() as f:
            table = json.load(f)
        for code in ErrorCode:
            key = format_code(int(code))
            assert key in table, f"missing description for {code.name} ({key})"

    def test_fallback_present(self) -> None:
        assert describe(0xFFF) == "Unknown error."

    def test_unknown_code_falls_back(self) -> None:
        # 0xDEA is not registered (0xD is unused system nibble)
        assert describe(0xDEA) == "Unknown error."

    def test_descriptions_independent_of_context(self) -> None:
        """Description lookup must NOT depend on context dict."""
        a = describe(0x111)
        b = describe(0x111)
        assert a == b
        # Even raising with very different contexts gives same description:
        e1 = CryptoError(code=ErrorCode.PADDING, context={"length": 13})
        e2 = CryptoError(code=ErrorCode.PADDING, context={"length": 99999, "extra": "junk"})
        assert describe(e1.code) == describe(e2.code)


class TestSeverity:
    def test_default_severity_error(self) -> None:
        e = CryptoError(code=ErrorCode.PADDING)
        assert e.severity == Severity.ERROR

    def test_overridden_class_severity(self) -> None:
        from protocol.errors import ErrorCode, KeyExchangeError, TransportError

        assert TransportError(code=ErrorCode.RATE_LIMITED).severity == Severity.WARNING
        assert KeyExchangeError(code=ErrorCode.KE_VERIFICATION).severity == Severity.CRITICAL

    def test_instance_severity_override(self) -> None:
        e = CryptoError(code=ErrorCode.PADDING, severity=Severity.WARNING)
        assert e.severity == Severity.WARNING


class TestContext:
    def test_context_copied_not_shared(self) -> None:
        ctx = {"a": 1}
        e = CryptoError(code=ErrorCode.PADDING, context=ctx)
        ctx["a"] = 99
        assert e.context["a"] == 1

    def test_no_context_yields_empty_dict(self) -> None:
        e = CryptoError(code=ErrorCode.PADDING)
        assert e.context == {}

    def test_cause_chain_preserved(self) -> None:
        inner = RuntimeError("root")
        e = CryptoError(code=ErrorCode.PADDING, cause=inner)
        assert e.__cause__ is inner


class _Sink:
    def __init__(self) -> None:
        self.calls: list[tuple[int, Severity, dict[str, Any] | None]] = []

    def on_error(
        self,
        code: int,
        severity: Severity,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.calls.append((code, severity, context))


class TestReportError:
    def test_forwards_chat_error(self) -> None:
        sink = _Sink()
        e = ServerError(code=ErrorCode.SRV_DD_AUTH, context={"name": "foo"})
        dispatch_error(sink, e)
        assert sink.calls == [(0x723, Severity.ERROR, {"name": "foo"})]

    def test_wraps_non_chat_error_as_0xfff(self) -> None:
        sink = _Sink()
        dispatch_error(sink, ValueError("boom"))
        assert len(sink.calls) == 1
        code, sev, ctx = sink.calls[0]
        assert code == 0xFFF
        assert sev == Severity.ERROR
        assert ctx is not None and ctx["original_type"] == "ValueError"

    def test_severity_override_propagates(self) -> None:
        sink = _Sink()
        e = TransportError(severity=Severity.CRITICAL)
        dispatch_error(sink, e)
        assert sink.calls[0][1] == Severity.CRITICAL

    def test_no_on_error_attr_is_silent(self) -> None:
        """Sink without ``on_error`` must not crash the protocol."""

        class Bare:
            pass

        dispatch_error(Bare(), CryptoError(code=ErrorCode.PADDING))  # should not raise

    def test_context_passed_as_new_dict(self) -> None:
        """Sink must receive a copy of context, not the exception's internal dict."""
        sink = _Sink()
        e = CryptoError(code=ErrorCode.PADDING, context={"x": 1})
        dispatch_error(sink, e)
        ctx = sink.calls[0][2]
        assert ctx is not None
        ctx["x"] = 999
        assert e.context["x"] == 1
