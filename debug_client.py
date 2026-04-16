"""
Debug Client — a subclass of SecureChatClient that logs every non-dummy
decrypted message to the UI's debug message log.

The UI is expected to expose a ``_log_message(direction, kind, content)``
method (as DebugGUI does).  If the method is absent the extra logging is
silently skipped so the client degrades gracefully with other UIs.
"""
from __future__ import annotations

import json
from typing import Any

from new_client import SecureChatClient
from protocol.constants import MessageType


class DebugClient(SecureChatClient):
    """SecureChatClient subclass that logs all non-dummy decrypted messages."""
    
    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------
    
    def _debug_log(self, kind: str, content: str) -> None:
        """Forward a log entry to the UI if it supports _log_message."""
        log_fn = getattr(self.ui, "_log_message", None)
        if callable(log_fn):
            log_fn("RECV", kind, content)
    
    # ------------------------------------------------------------------
    # Overridden dispatcher
    # ------------------------------------------------------------------
    
    def handle_message_types(
            self,
            message_type: MessageType,
            message_json: dict[str, Any],
            received_message_counter: int,
    ) -> bool:
        """Call the parent handler then log the message to the debug panel."""
        
        result = super().handle_message_types(
                message_type, message_json, received_message_counter,
        )
        
        # Skip dummy messages and unknown types (already logged as errors by parent)
        if message_type == MessageType.DUMMY_MESSAGE:
            return result
        
        match message_type:
            case MessageType.TEXT_MESSAGE:
                # Already logged by display_regular_message; skip to avoid duplicate
                pass
            
            case MessageType.FILE_METADATA:
                filename = message_json.get("filename", "<unknown>")
                size = message_json.get("file_size", "?")
                chunks = message_json.get("total_chunks", "?")
                self._debug_log(
                        "FILE_METADATA",
                        f"filename={filename!r} size={size} chunks={chunks}",
                )
            
            case MessageType.FILE_ACCEPT:
                transfer_id = message_json.get("transfer_id", "?")
                self._debug_log("FILE_ACCEPT", f"transfer_id={transfer_id!r}")
            
            case MessageType.FILE_REJECT:
                transfer_id = message_json.get("transfer_id", "?")
                reason = message_json.get("reason", "")
                self._debug_log(
                        "FILE_REJECT",
                        f"transfer_id={transfer_id!r} reason={reason!r}",
                )
            
            case MessageType.FILE_COMPLETE:
                transfer_id = message_json.get("transfer_id", "?")
                self._debug_log("FILE_COMPLETE", f"transfer_id={transfer_id!r}")
            
            case MessageType.DELIVERY_CONFIRMATION:
                counter = message_json.get("confirmed_counter", "?")
                self._debug_log("DELIVERY_CONFIRMATION", f"confirmed_counter={counter}")
            
            case MessageType.EPHEMERAL_MODE_CHANGE:
                mode = message_json.get("mode", "?")
                owner = message_json.get("owner_id", None)
                self._debug_log(
                        "EPHEMERAL_MODE_CHANGE",
                        f"mode={mode!r} owner_id={owner!r}",
                )
            
            case MessageType.REKEY:
                step = message_json.get("step", "?")
                self._debug_log("REKEY", f"msg={message_json}")
            
            case MessageType.VOICE_CALL_INIT:
                self._debug_log("VOICE_CALL_INIT", json.dumps(message_json))
            
            case MessageType.VOICE_CALL_ACCEPT:
                self._debug_log("VOICE_CALL_ACCEPT", json.dumps(message_json))
            
            case MessageType.VOICE_CALL_REJECT:
                self._debug_log("VOICE_CALL_REJECT", "(no payload)")
            
            case MessageType.VOICE_CALL_DATA:
                length = len(message_json.get("data", ""))
                self._debug_log("VOICE_CALL_DATA", f"data_len={length}")
            
            case MessageType.VOICE_CALL_END:
                self._debug_log("VOICE_CALL_END", "(no payload)")
            
            case MessageType.NICKNAME_CHANGE:
                new_nick = message_json.get("nickname", "?")
                self._debug_log("NICKNAME_CHANGE", f"nickname={new_nick!r}")
            
            case MessageType.EMERGENCY_CLOSE:
                self._debug_log("EMERGENCY_CLOSE", "(peer triggered emergency close)")
            
            case _:
                # Unknown / unhandled type — log raw JSON for visibility
                if result is False:
                    self._debug_log(
                            f"UNKNOWN({message_type})", json.dumps(message_json),
                    )
        
        return result
