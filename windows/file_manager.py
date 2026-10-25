"""
File Transfer Engine for LinkBridge Windows (`file_manager.py`).
Supports:
- Bidirectional streaming of any file type (TXT, PDF, DOCX, EPUB, images, audio, video, ZIP, code, unknown extensions treated strictly as untrusted binary data — never executed or auto-opened).
- Multiple files and nested folder structure preservation within the chosen receive directory.
- Strict Path Traversal defense: sanitizes filenames/relative paths, rejects `..`, drive letters, UNC paths, and verifies `.resolve().is_relative_to(receive_dir)`.
- Non-destructive collision handling: never overwrites an existing file silently; appends `(1)`, `(2)`, etc.
- Resumable chunked transfers: writes incoming chunks to `<transfer_id>.lbpart`, tracks byte offsets, supports `FILE_OFFER` with `resume_offset`, verifies final size + full-file SHA-256 before moving into place, and deletes `.lbpart` on cancel.
"""
import hashlib
import os
import re
import secrets
import time
from pathlib import Path, PurePath
from typing import Any, Callable, Dict, List, Optional, Tuple

from protocol.constants import MessageType
from protocol.crypto import compute_sha256_file
from protocol.messages import ProtocolFramingError
from protocol.transport import TransportAdapter, TransportError
from .storage import LocalStorage

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


class UnsafeFilePathError(Exception):
    """Raised when an incoming file name or relative path attempts path traversal or escapes receive_dir."""


class FileTransferManager:
    """
    Handles safe, chunked, resumable file sending and receiving over any TransportAdapter.
    """

    def __init__(
        self,
        local_device_id: str,
        storage: LocalStorage,
        on_progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        approval_prompt_callback: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ):
        self.local_device_id = local_device_id
        self.storage = storage
        self.on_progress_callback = on_progress_callback
        self.approval_prompt_callback = approval_prompt_callback
        self._cancelled_transfers: set[int] = set()

    @staticmethod
    def validate_and_resolve_destination(
        receive_dir: Path,
        offered_name_or_rel_path: str,
    ) -> Tuple[Path, str]:
        """
        Strictly validate an incoming file name or relative folder path:
        - Rejects empty names, null bytes, Windows drive letters (`C:`), UNC paths (`\\`), leading slashes, and `..` segments.
        - Sanitizes Windows-illegal characters (`<>:"|?*` and control chars) within each path component.
        - Verifies that the resolved path stays strictly inside `receive_dir.resolve()`.
        """
        if not offered_name_or_rel_path or "\x00" in offered_name_or_rel_path:
            raise UnsafeFilePathError("اسم الملف فارغ أو يحتوي على محارف غير صالحة (Invalid null/empty path)")

        raw = offered_name_or_rel_path.strip()
        # Reject absolute paths, UNC paths, or drive prefixes immediately
        if raw.startswith(("/", "\\")) or re.match(r"^[a-zA-Z]:", raw):
            raise UnsafeFilePathError(f"تم رفض مسار مطلق غير آمن: {offered_name_or_rel_path}")

        normalized = raw.replace("\\", "/")
        parts = [p for p in normalized.split("/") if p != ""]
        if not parts:
            raise UnsafeFilePathError("مسار الملف فارغ بعد التنظيف")

        safe_parts: List[str] = []
        for part in parts:
            if part in (".", ".."):
                raise UnsafeFilePathError(f"تم رفض محاولة اجتياز المسار (Path traversal rejected): {offered_name_or_rel_path}")
            # Check for illegal characters or control chars
            if re.search(r'[<>:"|?*\x00-\x1f]', part):
                raise UnsafeFilePathError(f"اسم الملف يحتوي على رموز غير مسموحة: {part}")
            stem = part.split(".")[0].upper()
            if stem in WINDOWS_RESERVED_NAMES:
                part = f"_{part}"
            safe_parts.append(part)

        receive_root = receive_dir.resolve()
        candidate = (receive_root / Path(*safe_parts)).resolve()
        if not candidate.is_relative_to(receive_root) or candidate == receive_root:
            raise UnsafeFilePathError("مسار الحفظ يخرج عن مجلد الاستقبال المحدد (Path escapes receive directory)")

        return candidate, "/".join(safe_parts)

    @staticmethod
    def resolve_non_conflicting_path(target_path: Path) -> Path:
        """
        If `target_path` already exists on disk, never overwrite it silently.
        Append ` (1)`, ` (2)`, etc. before the file suffix.
        """
        if not target_path.exists():
            return target_path
        parent = target_path.parent
        stem = target_path.stem
        suffix = target_path.suffix
        counter = 1
        while True:
            candidate = parent / f"{stem} ({counter}){suffix}"
            if not candidate.exists():
                return candidate
            counter += 1

    def cancel_transfer(self, transfer_id: int, transport: Optional[TransportAdapter] = None) -> None:
        """Cancel an in-progress transfer and safely remove its temporary `.lbpart` file."""
        self._cancelled_transfers.add(transfer_id)
        if transport and transport.is_connected:
            try:
                transport.send_control(
                    MessageType.FILE_CANCEL,
                    {"transfer_id": transfer_id, "reason": "تم إلغاء النقل من قبل المستخدم (Cancelled by user)"},
                    transfer_id=transfer_id,
                )
            except Exception:
                pass
        rec = self.storage.get_file_transfer(transfer_id)
        if rec:
            tmp = rec.get("temp_file_path", "")
            if tmp:
                p = Path(tmp)
                if p.exists() and p.suffix == ".lbpart":
                    try:
                        p.unlink()
                    except OSError:
                        pass
            self.storage.upsert_file_transfer(
                transfer_id=transfer_id,
                file_name=rec["file_name"],
                safe_rel_path=rec["safe_rel_path"],
                total_bytes=rec["total_bytes"],
                transferred_bytes=rec["transferred_bytes"],
                expected_sha256=rec["expected_sha256"],
                direction=rec["direction"],
                transport=rec["transport"],
                peer_device_id=rec["peer_device_id"],
                status="CANCELLED",
                temp_file_path="",
                final_file_path="",
                error_message="تم إلغاء النقل وحذف البيانات المؤقتة",
            )

    def send_file(
        self,
        transport: TransportAdapter,
        file_path: Path,
        rel_path: Optional[str] = None,
        transfer_id: Optional[int] = None,
        abort_after_bytes: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Stream a local file to the connected peer in chunks without loading the whole file into memory.
        Supports resuming from the byte offset reported by the receiver (`FILE_ACCEPT.resume_offset`).
        `abort_after_bytes` is an optional fault-injection hook for testing mid-transfer disconnection.
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"الملف غير موجود: {file_path}")

        total_bytes = file_path.stat().st_size
        max_mb = int(self.storage.get_setting("max_file_size_mb", 4096))
        if total_bytes > max_mb * 1024 * 1024:
            raise ValueError(f"حجم الملف يتجاوز الحد الأقصى المسموح به ({max_mb} ميجابايت)")

        expected_sha256 = compute_sha256_file(file_path, chunk_size=transport.chunk_size)
        transfer_id = transfer_id or (secrets.randbits(48) + 1)
        rel_name = rel_path or file_path.name

        self.storage.upsert_file_transfer(
            transfer_id=transfer_id,
            file_name=file_path.name,
            safe_rel_path=rel_name,
            total_bytes=total_bytes,
            transferred_bytes=0,
            expected_sha256=expected_sha256,
            direction="OUTGOING",
            transport=transport.transport_type.value,
            peer_device_id=transport.peer_device_id or "peer",
            status="OFFERED",
            final_file_path=str(file_path),
        )

        # 1. Send FILE_OFFER
        offer_body = {
            "transfer_id": transfer_id,
            "file_name": file_path.name,
            "rel_path": rel_name,
            "total_bytes": total_bytes,
            "sha256": expected_sha256,
            "chunk_size": transport.chunk_size,
        }
        transport.send_control(MessageType.FILE_OFFER, offer_body, transfer_id=transfer_id)

        # 2. Wait for FILE_ACCEPT or FILE_REJECT
        resp_frame = transport.receive_reply_frame()
        if resp_frame.header.msg_type == MessageType.FILE_REJECT:
            reason = resp_frame.json_body().get("reason", "تم رفض الملف من الطرف الآخر")
            self.storage.upsert_file_transfer(
                transfer_id=transfer_id,
                file_name=file_path.name,
                safe_rel_path=rel_name,
                total_bytes=total_bytes,
                transferred_bytes=0,
                expected_sha256=expected_sha256,
                direction="OUTGOING",
                transport=transport.transport_type.value,
                peer_device_id=transport.peer_device_id or "peer",
                status="REJECTED",
                final_file_path=str(file_path),
                error_message=reason,
            )
            return {"status": "REJECTED", "transfer_id": transfer_id, "reason": reason}

        if resp_frame.header.msg_type != MessageType.FILE_ACCEPT:
            raise ProtocolFramingError(f"Expected FILE_ACCEPT, got {resp_frame.header.msg_type}")

        accept_body = resp_frame.json_body()
        resume_offset = int(accept_body.get("resume_offset", 0))
        if resume_offset < 0 or resume_offset > total_bytes:
            resume_offset = 0

        # 3. Stream chunks starting from resume_offset
        sent_bytes = resume_offset
        start_time = time.time()
        with open(file_path, "rb") as f:
            if resume_offset > 0:
                f.seek(resume_offset)
            while sent_bytes < total_bytes:
                if transfer_id in self._cancelled_transfers:
                    raise TransportError("تم إلغاء النقل من قبل المستخدم")
                if abort_after_bytes is not None and sent_bytes >= abort_after_bytes:
                    transport.close()
                    raise TransportError("Simulated connection drop during file transfer")

                chunk = f.read(transport.chunk_size)
                if not chunk:
                    break
                transport.send_chunk(chunk, transfer_id=transfer_id)
                sent_bytes += len(chunk)
                elapsed = max(time.time() - start_time, 1e-4)
                rate_bps = (sent_bytes - resume_offset) / elapsed

                self.storage.upsert_file_transfer(
                    transfer_id=transfer_id,
                    file_name=file_path.name,
                    safe_rel_path=rel_name,
                    total_bytes=total_bytes,
                    transferred_bytes=sent_bytes,
                    expected_sha256=expected_sha256,
                    direction="OUTGOING",
                    transport=transport.transport_type.value,
                    peer_device_id=transport.peer_device_id or "peer",
                    status="IN_PROGRESS",
                    final_file_path=str(file_path),
                )
                if self.on_progress_callback:
                    self.on_progress_callback(
                        {
                            "transfer_id": transfer_id,
                            "file_name": file_path.name,
                            "direction": "OUTGOING",
                            "transferred_bytes": sent_bytes,
                            "total_bytes": total_bytes,
                            "rate_bytes_per_sec": rate_bps,
                            "resumed_from": resume_offset,
                        }
                    )

        # 4. Send FILE_COMPLETE and wait for FILE_VERIFY_RESULT
        transport.send_control(
            MessageType.FILE_COMPLETE,
            {
                "transfer_id": transfer_id,
                "total_bytes": total_bytes,
                "sha256": expected_sha256,
            },
            transfer_id=transfer_id,
        )
        verify_frame = transport.receive_reply_frame()
        if verify_frame.header.msg_type != MessageType.FILE_VERIFY_RESULT:
            raise ProtocolFramingError(f"Expected FILE_VERIFY_RESULT, got {verify_frame.header.msg_type}")

        vbody = verify_frame.json_body()
        verified = bool(vbody.get("verified", False))
        status = "COMPLETED" if verified else "FAILED"
        elapsed = max(time.time() - start_time, 1e-4)
        rate_bps = (sent_bytes - resume_offset) / elapsed

        self.storage.upsert_file_transfer(
            transfer_id=transfer_id,
            file_name=file_path.name,
            safe_rel_path=rel_name,
            total_bytes=total_bytes,
            transferred_bytes=sent_bytes,
            expected_sha256=expected_sha256,
            direction="OUTGOING",
            transport=transport.transport_type.value,
            peer_device_id=transport.peer_device_id or "peer",
            status=status,
            final_file_path=str(file_path),
            error_message="" if verified else vbody.get("reason", "فشل التحقق من البصمة"),
        )
        return {
            "status": status,
            "verified": verified,
            "transfer_id": transfer_id,
            "total_bytes": total_bytes,
            "resumed_from": resume_offset,
            "sha256": expected_sha256,
            "rate_bytes_per_sec": rate_bps,
            "remote_saved_path": vbody.get("saved_name", ""),
        }

    def send_directory(
        self,
        transport: TransportAdapter,
        directory_path: Path,
    ) -> List[Dict[str, Any]]:
        """Send all files inside a folder while preserving safe relative paths."""
        directory_path = Path(directory_path).resolve()
        if not directory_path.is_dir():
            raise NotADirectoryError(f"المجلد غير موجود: {directory_path}")
        results: List[Dict[str, Any]] = []
        base_name = directory_path.name
        for root, _, files in os.walk(directory_path):
            for fname in sorted(files):
                full_p = Path(root) / fname
                rel = f"{base_name}/{full_p.relative_to(directory_path).as_posix()}"
                res = self.send_file(transport, full_p, rel_path=rel)
                results.append(res)
        return results

    def receive_offered_file(
        self,
        transport: TransportAdapter,
        offer_frame_body: Dict[str, Any],
        transfer_id: int,
    ) -> Dict[str, Any]:
        """
        Handle an incoming `FILE_OFFER` and stream chunks to a `.lbpart` temporary file inside `receive_directory`:
        - Rejects unsafe paths (`..`, absolute, drive letters) before creating any file.
        - Rejects files exceeding `max_file_size_mb`.
        - Checks user approval if `auto_accept_files` is False.
        - Detects partial `.lbpart` from an interrupted prior attempt with matching `transfer_id` and `sha256` to support seamless resume!
        - Verifies final byte count and SHA-256 digest before atomically moving `.lbpart` to a non-conflicting final filename.
        """
        receive_dir = Path(self.storage.get_setting("receive_directory"))
        receive_dir.mkdir(parents=True, exist_ok=True)

        offered_rel = str(offer_frame_body.get("rel_path") or offer_frame_body.get("file_name") or "")
        total_bytes = int(offer_frame_body.get("total_bytes", -1))
        expected_sha256 = str(offer_frame_body.get("sha256", "")).lower()

        # 1. Path Traversal Check
        try:
            intended_dest, safe_rel = self.validate_and_resolve_destination(receive_dir, offered_rel)
        except UnsafeFilePathError as e:
            transport.send_control(
                MessageType.FILE_REJECT,
                {"transfer_id": transfer_id, "reason": str(e)},
                transfer_id=transfer_id,
            )
            return {"status": "REJECTED", "transfer_id": transfer_id, "reason": str(e)}

        # 2. Size Limit Check
        max_mb = int(self.storage.get_setting("max_file_size_mb", 4096))
        if total_bytes < 0 or total_bytes > max_mb * 1024 * 1024:
            reason = f"حجم الملف غير مسموح به ({total_bytes} بايت)"
            transport.send_control(
                MessageType.FILE_REJECT,
                {"transfer_id": transfer_id, "reason": reason},
                transfer_id=transfer_id,
            )
            return {"status": "REJECTED", "transfer_id": transfer_id, "reason": reason}

        # 3. User Approval Check (when auto_accept_files is False)
        auto_accept = bool(self.storage.get_setting("auto_accept_files", False))
        if not auto_accept and self.approval_prompt_callback is not None:
            approved = self.approval_prompt_callback(
                {
                    "transfer_id": transfer_id,
                    "file_name": intended_dest.name,
                    "safe_rel_path": safe_rel,
                    "total_bytes": total_bytes,
                    "peer_device_id": transport.peer_device_id,
                }
            )
            if not approved:
                reason = "تم رفض استقبال الملف من قبل المستخدم"
                transport.send_control(
                    MessageType.FILE_REJECT,
                    {"transfer_id": transfer_id, "reason": reason},
                    transfer_id=transfer_id,
                )
                return {"status": "REJECTED", "transfer_id": transfer_id, "reason": reason}

        # 4. Prepare temporary `.lbpart` file and check if resumable
        intended_dest.parent.mkdir(parents=True, exist_ok=True)
        temp_part_path = intended_dest.parent / f".lb_{transfer_id}_{intended_dest.name}.lbpart"
        existing_rec = self.storage.get_file_transfer(transfer_id)

        resume_offset = 0
        if (
            existing_rec
            and existing_rec.get("expected_sha256") == expected_sha256
            and temp_part_path.exists()
        ):
            current_part_size = temp_part_path.stat().st_size
            if 0 < current_part_size <= total_bytes:
                resume_offset = current_part_size
            else:
                temp_part_path.unlink(missing_ok=True)
        else:
            temp_part_path.unlink(missing_ok=True)

        self.storage.upsert_file_transfer(
            transfer_id=transfer_id,
            file_name=intended_dest.name,
            safe_rel_path=safe_rel,
            total_bytes=total_bytes,
            transferred_bytes=resume_offset,
            expected_sha256=expected_sha256,
            direction="INCOMING",
            transport=transport.transport_type.value,
            peer_device_id=transport.peer_device_id or "peer",
            status="IN_PROGRESS",
            temp_file_path=str(temp_part_path),
        )

        # Send FILE_ACCEPT with resume_offset
        transport.send_control(
            MessageType.FILE_ACCEPT,
            {
                "transfer_id": transfer_id,
                "resume_offset": resume_offset,
            },
            transfer_id=transfer_id,
        )

        # 5. Receive chunks and write to temp_part_path
        received_bytes = resume_offset
        mode = "ab" if resume_offset > 0 else "wb"
        start_time = time.time()

        try:
            with open(temp_part_path, mode) as out_f:
                while True:
                    frame = transport.receive_frame(max_payload_bytes=max(transport.chunk_size * 2, 131072))
                    if frame.header.msg_type == MessageType.FILE_CHUNK:
                        if frame.header.transfer_id != transfer_id:
                            raise ProtocolFramingError("Mismatched transfer_id on FILE_CHUNK")
                        out_f.write(frame.payload)
                        received_bytes += len(frame.payload)
                        if received_bytes > total_bytes:
                            raise ProtocolFramingError("Received more bytes than offered total_bytes")

                        elapsed = max(time.time() - start_time, 1e-4)
                        rate_bps = (received_bytes - resume_offset) / elapsed
                        self.storage.upsert_file_transfer(
                            transfer_id=transfer_id,
                            file_name=intended_dest.name,
                            safe_rel_path=safe_rel,
                            total_bytes=total_bytes,
                            transferred_bytes=received_bytes,
                            expected_sha256=expected_sha256,
                            direction="INCOMING",
                            transport=transport.transport_type.value,
                            peer_device_id=transport.peer_device_id or "peer",
                            status="IN_PROGRESS",
                            temp_file_path=str(temp_part_path),
                        )
                        if self.on_progress_callback:
                            self.on_progress_callback(
                                {
                                    "transfer_id": transfer_id,
                                    "file_name": intended_dest.name,
                                    "direction": "INCOMING",
                                    "transferred_bytes": received_bytes,
                                    "total_bytes": total_bytes,
                                    "rate_bytes_per_sec": rate_bps,
                                    "resumed_from": resume_offset,
                                }
                            )
                    elif frame.header.msg_type == MessageType.FILE_COMPLETE:
                        break
                    elif frame.header.msg_type == MessageType.FILE_CANCEL:
                        out_f.close()
                        temp_part_path.unlink(missing_ok=True)
                        self.storage.upsert_file_transfer(
                            transfer_id=transfer_id,
                            file_name=intended_dest.name,
                            safe_rel_path=safe_rel,
                            total_bytes=total_bytes,
                            transferred_bytes=received_bytes,
                            expected_sha256=expected_sha256,
                            direction="INCOMING",
                            transport=transport.transport_type.value,
                            peer_device_id=transport.peer_device_id or "peer",
                            status="CANCELLED",
                            temp_file_path="",
                            error_message="تم إلغاء النقل من المرسل وحذف الملف المؤقت",
                        )
                        return {"status": "CANCELLED", "transfer_id": transfer_id}
                    else:
                        raise ProtocolFramingError(f"Unexpected frame during file transfer: {frame.header.msg_type}")
        except ( EOFError, OSError, TransportError, ProtocolFramingError ) as e:
            # Keep `.lbpart` intact if connection dropped mid-stream so resume can succeed on reconnect!
            self.storage.upsert_file_transfer(
                transfer_id=transfer_id,
                file_name=intended_dest.name,
                safe_rel_path=safe_rel,
                total_bytes=total_bytes,
                transferred_bytes=received_bytes,
                expected_sha256=expected_sha256,
                direction="INCOMING",
                transport=transport.transport_type.value,
                peer_device_id=transport.peer_device_id or "peer",
                status="INTERRUPTED",
                temp_file_path=str(temp_part_path),
                error_message=f"انقطع الاتصال أثناء النقل عند {received_bytes}/{total_bytes} بايت (قابل للاستئناف): {e}",
            )
            raise

        # 6. Verify total size and full-file SHA-256
        actual_size = temp_part_path.stat().st_size
        actual_sha256 = compute_sha256_file(temp_part_path, chunk_size=transport.chunk_size).lower()

        if actual_size != total_bytes or actual_sha256 != expected_sha256:
            temp_part_path.unlink(missing_ok=True)
            reason = (
                f"فشل التحقق من سلامة الملف (الحجم المتوقع {total_bytes} الفعلي {actual_size}، "
                f"البصمة المتوقعة {expected_sha256[:12]}... الفعلية {actual_sha256[:12]}...)"
            )
            transport.send_control(
                MessageType.FILE_VERIFY_RESULT,
                {"transfer_id": transfer_id, "verified": False, "reason": reason},
                transfer_id=transfer_id,
            )
            self.storage.upsert_file_transfer(
                transfer_id=transfer_id,
                file_name=intended_dest.name,
                safe_rel_path=safe_rel,
                total_bytes=total_bytes,
                transferred_bytes=received_bytes,
                expected_sha256=expected_sha256,
                direction="INCOMING",
                transport=transport.transport_type.value,
                peer_device_id=transport.peer_device_id or "peer",
                status="FAILED",
                temp_file_path="",
                error_message=reason,
            )
            return {"status": "FAILED", "verified": False, "transfer_id": transfer_id, "reason": reason}

        # 7. Resolve filename collisions safely (never overwrite an existing file silently)
        final_dest = self.resolve_non_conflicting_path(intended_dest)
        temp_part_path.replace(final_dest)

        transport.send_control(
            MessageType.FILE_VERIFY_RESULT,
            {
                "transfer_id": transfer_id,
                "verified": True,
                "saved_name": final_dest.name,
                "sha256": actual_sha256,
            },
            transfer_id=transfer_id,
        )
        self.storage.upsert_file_transfer(
            transfer_id=transfer_id,
            file_name=final_dest.name,
            safe_rel_path=safe_rel,
            total_bytes=total_bytes,
            transferred_bytes=received_bytes,
            expected_sha256=expected_sha256,
            direction="INCOMING",
            transport=transport.transport_type.value,
            peer_device_id=transport.peer_device_id or "peer",
            status="COMPLETED",
            temp_file_path="",
            final_file_path=str(final_dest),
        )
        return {
            "status": "COMPLETED",
            "verified": True,
            "transfer_id": transfer_id,
            "final_path": final_dest,
            "saved_name": final_dest.name,
            "resumed_from": resume_offset,
            "sha256": actual_sha256,
        }
