"""What an ``insufficient_packet`` review named as missing, fenced and classified (issue #907).

The reviewer may name only refs its packet carried. FinishUP, not the reviewer, decides whether the
agent can supply each item: a kind the effective review selection or channel can never carry, or a
target the owner redacted, is ``structurally_unavailable_on_this_host``; content the packet cannot
show (an unsupported data type such as an image or binary file, content clipped or omitted for
packet room) is a ``yoetz_limit_*`` class (tb4n1 D1, #983);
everything else is ``agent_suppliable``. Only ``agent_suppliable`` is ever agent work. A later review sees the earlier request beside what was recorded since, and
an item re-requested after it was supplied is dropped unless the reviewer cites that new material.
"Supplied" is judged per named target: only new material directly tied to that target counts
(its run, exact command, file path, or a correction of it), so a record that relates only to
another path, run or claim never answers it. A re-run of the target's exact command that FinishUP
observed after the request counts for a targeted item too (W6, ADR-006 amendment), but a repeat
is never dropped as supplied for observed material the packet did not carry.

Reads the frozen projection and review selection. Its only filesystem access is resolving the
workspace root the caller supplies (an ``isdir`` check, then ``os.path.realpath``, once per
call); a path an agent recorded is compared lexically and never resolved or stat'ed.
"""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol, cast

from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    EvidenceContentAvailability,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceRecordedPayload,
    MissingForAssessmentItem,
    PlanPublishedPayload,
    PlanRevisedPayload,
    ResponseRecordedPayload,
    ResultRecordedPayload,
)
from finishup.domain.findings import Finding
from finishup.domain.privacy import ReviewSelectionPolicy
from finishup.domain.receipts import (
    SEMANTIC_MISSING_AGENT_SUPPLIABLE_GAP,
    SEMANTIC_MISSING_ALREADY_SUPPLIED_GAP,
    SEMANTIC_MISSING_FINISHUP_LIMIT_GAP,
    SEMANTIC_MISSING_ITEMS_REJECTED_GAP,
    SEMANTIC_MISSING_NON_CONVERGENT_GAP,
    SEMANTIC_MISSING_UNAVAILABLE_GAP,
)
from finishup.domain.values import EventId
from finishup.kernel.delivered_set import item_role
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.projections import PendingMissingForAssessment, ProjectionState
from finishup.kernel.task_facts import effective_obligations, requested_command_identity
from finishup.ports.change_capture import CheckChangeCapture
from finishup.ports.semantic import SemanticJudgment
from finishup.protocol.models import (
    MAX_MISSING_FOR_ASSESSMENT,
    MAX_REVIEW_FOLLOW_UP_ROUNDS,
    MISSING_FOR_ASSESSMENT_KINDS,
    DataCategory,
)

__all__ = [
    "CHECK_TIME_CHANGE_SOURCE_REF",
    "FOLLOW_UP_KINDS",
    "FINISHUP_LIMIT_PACKET_ROOM",
    "FINISHUP_LIMIT_UNSUPPORTED_DATA_TYPE",
    "MissingItemsReview",
    "ReviewFollowUp",
    "ReviewFollowUpItem",
    "check_change_binary_paths",
    "check_change_text_paths",
    "command_run_key",
    "excerpt_span",
    "excerpt_span_covered",
    "excerpt_span_key",
    "excerpt_span_whole",
    "OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX",
    "observed_command_output_refs",
    "observed_enrichment_refs",
    "observed_image_evidence",
    "plan_review_follow_up",
    "review_missing_for_assessment",
    "supplied_since",
    "unsupported_data_type",
    "unsuppliable_missing_kinds",
]

AGENT_SUPPLIABLE: Final = "agent_suppliable"
STRUCTURALLY_UNAVAILABLE: Final = "structurally_unavailable_on_this_host"
# FinishUP's own review limits (tb4n1 D1, issue #983): content the packet cannot show is never work
# for the agent. The agent verifies such an item itself and the receipt discloses the limit; it
# must never split, move, shrink, stash, delete, git-add or git-ignore its work to fit the packet.
FINISHUP_LIMIT_UNSUPPORTED_DATA_TYPE: Final = "yoetz_limit_unsupported_data_type"
FINISHUP_LIMIT_PACKET_ROOM: Final = "yoetz_limit_packet_room"
# Content the review packet never carries: images, audio, video, documents, archives, disk
# images, CAD/EDA, fonts, ROMs, data and model files, databases, native objects and captures
# (tb4n2 A11). Matched on the file name a target records, case-insensitively, on its last suffix
# (so ``x.tar.zst`` matches ``.zst``). The check-time change's own NUL-byte sniff decides first
# (ADR-045): a file Git found binary is unsupported, and a file it found text is not, whatever its
# suffix; the suffix decides only for a file the change did not list. ISO 10303-21 ``.step`` and
# ``.stp`` are ASCII, so they are not here. A few suffixes also name text formats (``.key`` a PEM key,
# ``.nc`` G-code, ``.hdr`` an ENVI header, ``.brd``/``.svf``/``.fig``/``.gb`` text board, vector,
# figure or GenBank files): they are listed anyway, because a false FinishUP limit only means the
# agent verifies the file itself under a disclosed limit, while a false "agent work" pushes the
# agent to reshape a deliverable for the reviewer. A suffix-less binary is recognised from the
# check-time change instead (``check_change_binary_paths``).
_UNSUPPORTED_SUFFIXES: Final = frozenset(
    {
        ".3dm",
        ".3mf",
        ".7z",
        ".a",
        ".aac",
        ".aar",
        ".accdb",
        ".aiff",
        ".apk",
        ".arrow",
        ".avi",
        ".avif",
        ".avro",
        ".beam",
        ".bin",
        ".bit",
        ".blend",
        ".bmp",
        ".brd",
        ".bz2",
        ".cab",
        ".catpart",
        ".ckpt",
        ".class",
        ".cr2",
        ".db",
        ".db3",
        ".deb",
        ".dll",
        ".dmg",
        ".dng",
        ".doc",
        ".docx",
        ".dta",
        ".duckdb",
        ".dwg",
        ".dxf",
        ".dylib",
        ".ear",
        ".egg",
        ".elf",
        ".epub",
        ".exe",
        ".exr",
        ".f3d",
        ".fbx",
        ".fcstd",
        ".feather",
        ".fig",
        ".flac",
        ".gb",
        ".gba",
        ".gds",
        ".ggml",
        ".gguf",
        ".gif",
        ".glb",
        ".gz",
        ".h5",
        ".hdf",
        ".hdf5",
        ".hdr",
        ".heic",
        ".iam",
        ".ico",
        ".iges",
        ".igs",
        ".img",
        ".ipa",
        ".ipt",
        ".iso",
        ".jar",
        ".joblib",
        ".jp2",
        ".jpeg",
        ".jpg",
        ".jxl",
        ".keras",
        ".key",
        ".ko",
        ".lib",
        ".lmdb",
        ".lz4",
        ".lzma",
        ".m4a",
        ".m4v",
        ".mat",
        ".mdb",
        ".mid",
        ".midi",
        ".mkv",
        ".mlmodel",
        ".mov",
        ".mp3",
        ".mp4",
        ".mscz",
        ".msi",
        ".mxl",
        ".nc",
        ".nef",
        ".nes",
        ".npy",
        ".npz",
        ".numbers",
        ".nupkg",
        ".o",
        ".oas",
        ".odp",
        ".ods",
        ".odt",
        ".ogg",
        ".onnx",
        ".opus",
        ".orc",
        ".otf",
        ".pages",
        ".parquet",
        ".pb",
        ".pcap",
        ".pcapng",
        ".pdf",
        ".pickle",
        ".pkl",
        ".png",
        ".ppt",
        ".pptx",
        ".psd",
        ".pt",
        ".pth",
        ".pyc",
        ".pyd",
        ".qcow2",
        ".rar",
        ".raw",
        ".rdata",
        ".rds",
        ".rom",
        ".rpm",
        ".sab",
        ".safetensors",
        ".sav",
        ".sfc",
        ".sif",
        ".sketch",
        ".skp",
        ".sldasm",
        ".sldprt",
        ".so",
        ".sqlite",
        ".sqlite3",
        ".stl",
        ".svf",
        ".tar",
        ".tflite",
        ".tfrecord",
        ".tga",
        ".tgz",
        ".tif",
        ".tiff",
        ".ttf",
        ".vmdk",
        ".war",
        ".wasm",
        ".wav",
        ".webm",
        ".webp",
        ".whl",
        ".wma",
        ".wmv",
        ".woff",
        ".woff2",
        ".x_b",
        ".xls",
        ".xlsx",
        ".xz",
        ".zip",
        ".zst",
    }
)
# How many refs recorded since the request the next packet names per item, newest first.
_MAX_SUPPLIED_REFS: Final = 4
# Which recorded families can answer each missing kind. ``output_results`` are results that
# carry output (linked evidence or a summary): a bare outcome row names a run but not what it
# printed, so it can never answer a request for verification output.
_ANSWERING_FAMILIES: Final[Mapping[str, tuple[str, ...]]] = {
    "command_identity": ("actions", "results", "evidence"),
    "current_diff_for_path": ("evidence",),
    "other": ("evidence", "results"),
    "plan_or_claim_text": ("plans", "claims"),
    "prior_finding_context": ("responses",),
    "task_statement": ("plans",),
    "verification_output": ("evidence", "output_results"),
}
_FAMILY_NAMES: Final = (
    "actions",
    "results",
    "output_results",
    "evidence",
    "claims",
    "plans",
    "responses",
)


@dataclass(frozen=True, slots=True)
class MissingItemsReview:
    """The fenced, classified items a check records, and the coverage gaps they imply."""

    items: tuple[MissingForAssessmentItem, ...]
    gaps: frozenset[str]


# Issue #1047: the kinds whose content FinishUP itself can carry as recorded excerpts (the edit a
# hook captured, a run's recorded output, its exact command). Every other kind (a task statement,
# plan or claim text, finding context, ``other``) is never answered by FinishUP inside the check.
FOLLOW_UP_KINDS: Final = frozenset(
    {"command_identity", "current_diff_for_path", "verification_output"}
)
# Only content FinishUP holds and did not show: a target the agent could supply or one the packet
# had no room for. A privacy-withheld, redacted or unsupported target is never re-sent.
_FOLLOW_UP_AVAILABILITIES: Final = frozenset({AGENT_SUPPLIABLE, FINISHUP_LIMIT_PACKET_ROOM})


@dataclass(frozen=True, slots=True)
class ReviewFollowUpItem:
    """One reviewer request FinishUP answers from its records (issue #1047).

    ``source_refs`` are the recorded rows whose excerpts carry the targets' content: each
    target, the rows an ``evt_`` target recorded, and for a run (an action or its result) the
    run's results, its action and the evidence those results cite. Redacted rows never count.
    """

    kind: str
    target_refs: tuple[str, ...]
    source_refs: frozenset[str]

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in FOLLOW_UP_KINDS:
            raise ValueError("review_follow_up_invalid")
        if (
            type(self.target_refs) is not tuple
            or not self.target_refs
            or any(type(ref) is not str for ref in self.target_refs)
        ):
            raise ValueError("review_follow_up_invalid")
        if type(self.source_refs) is not frozenset or not self.source_refs:
            raise ValueError("review_follow_up_invalid")


# The source ref of the service's own check-time change excerpts (ADR-031); never a ledger ref.
CHECK_TIME_CHANGE_SOURCE_REF: Final = "check-time-change"
# Span prefix of a follow-up excerpt that carries hook-captured command output (issue #1079).
# The bytes are the command the agent ran, marked observed; the prefix is not a ledger ref.
OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX: Final = "observed-command-output:"
# One excerpt part's place in its source (tb4n5, #1047 follow-up): ``<ref>#<start>-<end>/<total>``,
# the byte interval of the source's excerpt text the part holds and that text's length. The
# source is the candidate's own ref (a captured group's lead, ``check-time-change`` for the
# service's change). Comparing intervals, never part numbers, keeps the record exact when a
# narrowed case splits a source into different parts. In process only; never recorded or logged.
_SPAN_KEY: Final = re.compile(r"^(.+)#([0-9]{1,12})-([0-9]{1,12})/([0-9]{1,12})$")


def excerpt_span_key(ref: str, start: int, end: int, total: int) -> str:
    """The key of the excerpt part holding ``[start, end)`` of a ``total``-byte source text."""

    if not 0 <= start < end <= total:
        raise ValueError("excerpt_span_invalid")
    return f"{ref}#{start}-{end}/{total}"


def excerpt_span(key: str) -> tuple[str, int, int, int] | None:
    """``(source, start, end, total)`` of one ``excerpt_span_key``; ``None`` if malformed."""

    return _span(key)


def _span(key: str) -> tuple[str, int, int, int] | None:
    match = _SPAN_KEY.match(key)
    if match is None:
        return None
    return match.group(1), int(match.group(2)), int(match.group(3)), int(match.group(4))


def _covered(source: tuple[str, int], start: int, end: int, keys: Iterable[str]) -> bool:
    """Whether the union of ``keys``' intervals of ``source`` covers ``[start, end)``."""

    intervals = sorted(
        (span[1], span[2])
        for key in keys
        if (span := _span(key)) is not None and (span[0], span[3]) == source
    )
    reached = start
    for low, high in intervals:
        if low > reached:
            break
        reached = max(reached, high)
        if reached >= end:
            return True
    return reached >= end


def excerpt_span_covered(key: str, keys: Iterable[str]) -> bool:
    """Whether the bytes of the part ``key`` names all lie in parts ``keys`` name."""

    span = _span(key)
    return span is not None and _covered((span[0], span[3]), span[1], span[2], keys)


def excerpt_span_whole(key: str, keys: Iterable[str]) -> bool:
    """Whether ``keys`` cover the whole source text the part ``key`` belongs to."""

    span = _span(key)
    return span is not None and _covered((span[0], span[3]), 0, span[3], keys)


@dataclass(frozen=True, slots=True)
class ReviewFollowUp:
    """One in-check follow-up round: the reviewer asked, FinishUP adds what it holds (#1047).

    ``items`` accumulate in request order across the check's rounds, so what an earlier round
    added keeps its place in every later packet. ``shown_refs`` are the refs whose content the
    excerpts of the check's own first sent packet held whole; ``shown_parts`` the excerpt parts
    (``excerpt_span_key``) that packet carried, so a source it showed only in part still has
    parts to add (tb4n5). ``added_refs`` is what earlier sent packets completed, plus what egress
    withheld from a sent packet under a privacy rule (that rule withholds it from every packet);
    ``added_parts`` the parts earlier follow-up packets carried that no packet before them had. A
    round whose packet would carry no requested part beyond those is never sent. In process only;
    never recorded or logged.
    """

    round: int
    items: tuple[ReviewFollowUpItem, ...]
    shown_refs: frozenset[str]
    added_refs: frozenset[str] = frozenset()
    shown_parts: frozenset[str] = frozenset()
    added_parts: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if type(self.round) is not int or not 1 <= self.round <= MAX_REVIEW_FOLLOW_UP_ROUNDS:
            raise ValueError("review_follow_up_invalid")
        if (
            type(self.items) is not tuple
            or not 1 <= len(self.items) <= MAX_MISSING_FOR_ASSESSMENT
            or any(type(item) is not ReviewFollowUpItem for item in self.items)
        ):
            raise ValueError("review_follow_up_invalid")
        if any(
            type(value) is not frozenset or any(type(ref) is not str for ref in value)
            for value in (self.shown_refs, self.added_refs, self.shown_parts, self.added_parts)
        ):
            raise ValueError("review_follow_up_invalid")

    @property
    def source_refs(self) -> frozenset[str]:
        return frozenset(ref for item in self.items for ref in item.source_refs)

    @property
    def seen_parts(self) -> frozenset[str]:
        """Every excerpt part a sent packet of this check carried."""

        return self.shown_parts | self.added_parts

    def added_by(self, carried_excerpt_refs: Iterable[str]) -> frozenset[str]:
        """The requested source refs a packet carrying these excerpts shows beyond the first."""

        return (frozenset(carried_excerpt_refs) & self.source_refs) - self.shown_refs

    def unseen(self, parts: Iterable[str]) -> frozenset[str]:
        """The excerpt parts no sent packet of this check carried all of."""

        seen = self.seen_parts
        return frozenset(part for part in parts if not excerpt_span_covered(part, seen))


def plan_review_follow_up(
    projection: ProjectionState,
    allowed: frozenset[str],
    requested: Iterable[MissingForAssessmentItem],
    *,
    previous: ReviewFollowUp | None,
    shown_refs: frozenset[str] | None,
    privacy_withheld_refs: frozenset[str] = frozenset(),
    shown_parts: frozenset[str] | None = None,
    section_parts: Mapping[str, frozenset[str]] | None = None,
) -> ReviewFollowUp | None:
    """The next in-check follow-up round, or ``None`` when FinishUP has nothing it may add (#1047).

    ``requested`` is the latest ``insufficient_packet`` request, already fenced and classified by
    ``review_missing_for_assessment``. Only a ``FOLLOW_UP_KINDS`` item the agent could supply or
    the packet had no room for, naming targets FinishUP holds rows for, is answered here; every
    other item stays the agent's (or FinishUP's disclosed) business exactly as before. A round runs
    only while the reviewer still names such an item, fewer than ``MAX_REVIEW_FOLLOW_UP_ROUNDS``
    rounds ran, and some requested source is neither shown whole by the first packet nor
    completed already: a source the first packet showed only in part still has parts to add
    (tb4n5). ``shown_refs`` (what the first sent packet's excerpts held whole) is ``None`` when it
    is unknown: then nothing can be called added, so no round runs. ``shown_parts`` are the
    excerpt parts that packet carried (``None``: none known). ``privacy_withheld_refs`` are the
    refs the latest sent packet withheld under a privacy rule; they join ``added_refs``, since
    sending them again would only spend a round. ``section_parts`` maps each captured edit's
    evidence ref to the check-time change sections of the paths it changed
    (``semantic_case.current_section_parts``): a ``current_diff_for_path`` request for that edit
    is still owed while some of those bytes no packet carried, even when the edit itself was
    shown whole. Whether a round's packet really adds a part is decided once it is composed
    (``semantic_case.follow_up_new_parts``). A ``verification_output`` item also names
    hook-captured output of the newest run of each command its targets name. That output stays
    owed until a sent packet carried its observed span, even when a digest of the same evidence
    was shown whole. Selection, not this planner, applies the repository-excerpt gate.
    """

    if previous is not None and previous.round >= MAX_REVIEW_FOLLOW_UP_ROUNDS:
        return None
    shown = previous.shown_refs if previous is not None else shown_refs
    if shown is None:
        return None
    items = list(() if previous is None else previous.items)
    known = {(item.kind, item.target_refs) for item in items}
    asked = False
    for entry in requested:
        if (
            entry.kind not in FOLLOW_UP_KINDS
            or entry.availability not in _FOLLOW_UP_AVAILABILITIES
            or not entry.target_refs
        ):
            continue
        sources = _recorded_sources(projection, entry.target_refs, allowed)
        if entry.kind == "verification_output":
            # Maintainer-approved (issue #1079): hook-captured output of a command this
            # target names may ride the follow-up. Selection still applies the repository
            # excerpt gate, the privacy policy and the existing byte limits.
            sources |= observed_command_output_refs(projection, entry.target_refs, allowed)
        if not sources:
            continue
        asked = True
        key = (entry.kind, entry.target_refs)
        if key in known or len(items) >= MAX_MISSING_FOR_ASSESSMENT:
            continue
        known.add(key)
        items.append(ReviewFollowUpItem(entry.kind, entry.target_refs, sources))
    if not asked or not items:
        return None
    added: frozenset[str] = frozenset() if previous is None else previous.added_refs
    added |= privacy_withheld_refs & frozenset(ref for item in items for ref in item.source_refs)
    follow_up = ReviewFollowUp(
        1 if previous is None else previous.round + 1,
        tuple(items),
        shown,
        added,
        shown_parts=(
            previous.shown_parts if previous is not None else (shown_parts or frozenset())
        ),
        added_parts=frozenset() if previous is None else previous.added_parts,
    )
    observed_refs = frozenset(
        ref
        for item in follow_up.items
        if item.kind == "verification_output"
        for ref in observed_command_output_refs(projection, item.target_refs, allowed)
    )
    if (
        not follow_up.source_refs - shown - added
        and not _current_section_pending(follow_up, section_parts or {})
        and not _observed_output_pending(follow_up, observed_refs)
    ):
        return None
    return follow_up


def _current_section_pending(
    follow_up: ReviewFollowUp, section_parts: Mapping[str, frozenset[str]]
) -> bool:
    """Whether a ``current_diff_for_path`` item's current file sections still have bytes no
    packet of the check carried (tb4n5).

    The current section of a path an edit changed comes from the check-time change, not from
    the edit's own rows, so it can be owed even when the first packet showed the edit whole.
    Judged per requested path, never by whether any other bytes of the change remain unseen.
    """

    seen = follow_up.seen_parts
    return any(
        not excerpt_span_covered(key, seen)
        for item in follow_up.items
        if item.kind == "current_diff_for_path"
        for ref in item.source_refs
        for key in section_parts.get(ref, ())
    )


def _observed_output_pending(follow_up: ReviewFollowUp, observed_refs: frozenset[str]) -> bool:
    """Whether a verification-output item still owes marked hook-captured command output.

    A digest excerpt of the same evidence can be shown whole while the captured bytes were
    not. The marked follow-up excerpt uses ``OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX``, so the
    round stays owed until a sent packet carried that span. Evidence the target does not
    name, and evidence that is not hook-captured command output, is never in ``observed_refs``.
    """

    seen = follow_up.seen_parts
    prefix = OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX
    return any(
        not any(part.startswith(f"{prefix}{ref}#") for part in seen)
        for ref in observed_refs & follow_up.source_refs
    )


def _recorded_sources(
    projection: ProjectionState, targets: Iterable[str], allowed: frozenset[str]
) -> frozenset[str]:
    """The recorded rows whose excerpts carry what ``targets`` name (see ``ReviewFollowUpItem``).

    Only action, result and evidence rows can carry an excerpt. A target that names none of them
    and records none (an obligation, or the event that carried the task statement) is no source:
    a request naming only such targets is the agent's to answer, and planning a round for it only
    rebuilt the case to send nothing (tb4n5 react-lead-form, 19:35:05).
    """

    refs = set(targets)
    enrichments = observed_enrichment_refs(projection)
    for family in (projection.actions, projection.results, projection.evidence):
        for key, row in family.items():
            if str(row.source_event_id) in refs:
                refs.add(str(key))
    named = frozenset(refs)
    for key, row in projection.results.items():
        payload = row.payload
        if payload is None or row.redacted:
            continue
        if str(key) in named or str(payload.action_id) in named:
            action = projection.actions.get(payload.action_id)
            refs.update(
                (str(key), str(payload.action_id), *(str(ref) for ref in payload.evidence_refs))
            )
            if action is not None:
                refs.update(enrichments.get(str(action.source_event_id), ()))
    rows = {
        str(key)
        for family in (projection.actions, projection.results, projection.evidence)
        for key in family
    }
    return frozenset(refs & allowed & rows) - _redacted_refs(projection)


def observed_command_output_refs(
    projection: ProjectionState, targets: Iterable[str], allowed: frozenset[str]
) -> frozenset[str]:
    """Hook-captured output of commands ``targets`` name, for a verification-output follow-up.

    Only evidence a command result cites, stamped ``observation_captured``, allowed, and not
    redacted. The newest run of each named command wins. A readable command action that no
    readable result cites occupies that command: a tombstoned result no longer names its action,
    so an older capture is not substituted. A tombstoned action has no command text left and
    cannot occupy a key. A command with no run key (``omitted:structural``) identifies nothing
    and is not included: unrelated commands must not be grouped, and a keyless capture is not
    auto-supplied. Output of a command the targets do not name, and tool output an edit or file
    read recorded, is never included. This names refs only; whether the bytes may leave is the
    repository excerpt gate in selection.
    """

    named = {ref for ref in targets if type(ref) is str}
    if not named:
        return frozenset()
    evidence_events = {
        str(ref): str(row.source_event_id) for ref, row in projection.evidence.items()
    }
    enrichments = observed_enrichment_refs(projection)
    claim_supports: list[frozenset[str]] = []
    for claim_ref, row in projection.claims.items():
        payload = row.payload
        if payload is None or row.redacted:
            continue
        if str(claim_ref) not in named and str(row.source_event_id) not in named:
            continue
        claim_supports.append(frozenset(str(ref) for ref in payload.supporting_refs))

    # ``(key, frontier, result ref, evidence refs, redacted, directly named, related)``.
    # A redacted newest run still occupies the command so an older capture is not substituted.
    # The result payload is what named the action, so a tombstone cannot cite it; the readable
    # action occupies the key instead.
    runs: list[tuple[_RunKey | None, int, str, tuple[str, ...], bool, bool, bool]] = []
    cited_actions: set[object] = set()
    for result_ref, row in projection.results.items():
        payload = row.payload
        if payload is None:
            continue
        cited_actions.add(payload.action_id)
        action_row = projection.actions.get(payload.action_id)
        if (
            action_row is None
            or action_row.payload is None
            or action_row.redacted
            or action_row.payload.action_kind is not ActionKind.COMMAND
        ):
            continue
        action = action_row.payload
        key = _run_key(action)
        evidence_refs = tuple(
            sorted(
                {
                    *(str(ref) for ref in payload.evidence_refs),
                    *enrichments.get(str(action_row.source_event_id), ()),
                },
                key=str.encode,
            )
        )
        tokens = {
            str(result_ref),
            str(row.source_event_id),
            str(payload.action_id),
            str(action_row.source_event_id),
            *evidence_refs,
            *(evidence_events.get(ref, "") for ref in evidence_refs),
        }
        tokens.discard("")
        direct = bool(named & tokens)
        related = any(str(ref) in named for ref in action.obligation_refs) or any(
            supports & tokens for supports in claim_supports
        )
        if key is None:
            # No identity: do not group this run with any other, and do not auto-supply it.
            continue
        runs.append(
            (
                key,
                row.source_frontier,
                str(result_ref),
                evidence_refs,
                row.redacted,
                direct,
                related,
            )
        )
    for action_ref, action_row in projection.actions.items():
        if action_ref in cited_actions:
            continue
        action_payload = action_row.payload
        if (
            action_payload is None
            or action_row.redacted
            or action_payload.action_kind is not ActionKind.COMMAND
        ):
            continue
        key = _run_key(action_payload)
        if key is None:
            continue
        tokens = {str(action_ref), str(action_row.source_event_id)}
        runs.append(
            (
                key,
                action_row.source_frontier,
                str(action_ref),
                (),
                True,
                bool(named & tokens),
                any(str(ref) in named for ref in action_payload.obligation_refs)
                or any(supports & tokens for supports in claim_supports),
            )
        )

    named_keys = {run[0] for run in runs if run[0] is not None and (run[5] or run[6])}
    newest: dict[_RunKey, tuple[int, bytes, tuple[str, ...], bool]] = {}
    for key, frontier, result_ref, evidence_refs, redacted, _direct, _related in runs:
        if key is None or key not in named_keys:
            continue
        current = newest.get(key)
        rank = (frontier, result_ref.encode("ascii"))
        if current is None or rank > (current[0], current[1]):
            newest[key] = (frontier, rank[1], evidence_refs, redacted)

    chosen: list[str] = []
    for _frontier, _result_id, evidence_refs, redacted in newest.values():
        if not redacted:
            chosen.extend(evidence_refs)

    redacted_refs = _redacted_refs(projection)
    kept: set[str] = set()
    by_ref = {str(ref): row for ref, row in projection.evidence.items()}
    for ref in chosen:
        if ref not in allowed or ref in redacted_refs:
            continue
        row = by_ref.get(ref)
        if row is None or row.redacted or row.payload is None or not _hook_observed(row.payload):
            continue
        kept.add(ref)
    return frozenset(kept)


def observed_enrichment_refs(projection: ProjectionState) -> dict[str, tuple[str, ...]]:
    """Late evidence linked by the observation writer to its immutable original action.

    Only service-stamped captured provenance qualifies. The link does not advance the run's
    frontier, bypass a redacted result, or replace authenticated command/output binding.
    """

    linked: dict[str, list[str]] = {}
    for ref, row in projection.evidence.items():
        payload = row.payload
        if payload is not None and not row.redacted and _hook_observed(payload):
            if payload.reference is not None:
                linked.setdefault(payload.reference, []).append(str(ref))
    return {key: tuple(values) for key, values in linked.items()}


def unsuppliable_missing_kinds(
    selection: ReviewSelectionPolicy, withheld_categories: Iterable[str]
) -> tuple[str, ...]:
    """Kinds the effective selection and channel can never carry, whatever the agent records.

    Publishing more material does not help when the approved review selection drops its section
    or excerpt kind, or the inference channel withholds its category; that is a limitation of this
    host's configuration, not work the agent can do.
    """

    withheld = frozenset(withheld_categories)
    sections = frozenset(selection.sections)
    kinds = frozenset(selection.excerpt_kinds)
    excerpts = (
        "targeted_excerpts" in sections
        and selection.max_excerpts > 0
        and DataCategory.EVIDENCE_EXCERPT.value not in withheld
    )
    goal = "goal" in sections and DataCategory.TASK_DESCRIPTION.value not in withheld
    claims = "claims" in sections and DataCategory.CLAIM_TEXT.value not in withheld
    carried = {
        "command_identity": (
            "targeted_excerpts" in sections
            and selection.max_excerpts > 0
            and selection.include_exact_command_text
            and "command" in kinds
            and DataCategory.COMMAND_METADATA.value not in withheld
        ),
        "current_diff_for_path": excerpts and bool({"diff", "evidence"} & kinds),
        "other": excerpts,
        "plan_or_claim_text": goal or claims,
        "prior_finding_context": (
            "timeline" in sections and DataCategory.FINDING_SUMMARY.value not in withheld
        ),
        "task_statement": goal,
        "verification_output": excerpts
        and bool({"command", "evidence", "failure", "test"} & kinds),
    }
    if frozenset(carried) != MISSING_FOR_ASSESSMENT_KINDS:
        raise RuntimeError("missing_for_assessment_kinds_incomplete")
    return tuple(sorted((kind for kind, ok in carried.items() if not ok), key=str.encode))


def supplied_since(
    projection: ProjectionState,
    pending: PendingMissingForAssessment,
    allowed: frozenset[str],
    observation_event_ids: frozenset[str] = frozenset(),
    captured_edit_paths: Mapping[str, frozenset[str]] | None = None,
    workspace_root: str | None = None,
) -> tuple[tuple[str, ...], ...]:
    """For each pending item, the case refs of answering material recorded after the request.

    A targeted item counts only new material directly tied to one of its targets (see ``_Links``;
    ``captured_edit_paths`` maps a hook-captured edit's evidence refs to the workspace-relative
    paths its authenticated bytes record, used only to compare); an item with no target counts
    any answering material of its kind. FinishUP cannot bind new material to reviewer prose, so the
    next reviewer reads these refs and decides whether they answer the request.
    """

    answered: list[tuple[str, ...]] = []
    for per_target in _answers_by_target(
        projection, pending, allowed, observation_event_ids, captured_edit_paths, workspace_root
    ):
        newest = sorted(
            {entry for entries in per_target.values() for entry in entries},
            key=lambda entry: (-entry[0], entry[1].encode("ascii")),
        )
        answered.append(
            tuple(sorted((ref for _order, ref in newest[:_MAX_SUPPLIED_REFS]), key=str.encode))
        )
    return tuple(answered)


def _answers_by_target(
    projection: ProjectionState,
    pending: PendingMissingForAssessment,
    allowed: frozenset[str],
    observation_event_ids: frozenset[str],
    captured_edit_paths: Mapping[str, frozenset[str]] | None = None,
    workspace_root: str | None = None,
) -> tuple[dict[str | None, tuple[tuple[int, str], ...]], ...]:
    """Per pending item and target, the answering material recorded since, as ``(order, ref)``.

    The key ``None`` holds an untargeted item's answers, matched by record family alone.
    """

    after = pending.source_frontier
    links = _Links.of(
        projection,
        after,
        observation_event_ids,
        captured_edit_paths or {},
        workspace_root,
        request_event_id=str(pending.source_check_event_id),
    )
    observed_material = links.observed_material()
    recorded: dict[str, list[tuple[int, str]]] = {family: [] for family in _FAMILY_NAMES}
    # W6: hook-observed rows of a re-run of a target's exact command, for targeted items only. A
    # stray observed command never answers an untargeted request.
    recorded_observed: dict[str, list[tuple[int, str]]] = {family: [] for family in _FAMILY_NAMES}
    for family, rows in (
        ("actions", projection.actions),
        ("results", projection.results),
        ("evidence", projection.evidence),
        ("claims", projection.claims),
    ):
        for ref, row in rows.items():
            if row.source_frontier > after and row.payload is not None and not row.redacted:
                target = recorded
                if str(row.source_event_id) in observation_event_ids or _hook_observed(row.payload):
                    # Hook capture records every tool call; it is never the agent answering a
                    # named request by itself, so it must not turn a still-missing item into
                    # "supplied". Only a re-run of a target's own command answers (``_Links``).
                    if str(ref) not in observed_material:
                        continue
                    target = recorded_observed
                target[family].append((row.source_frontier, str(ref)))
                if type(row.payload) is ResultRecordedPayload and (
                    # An observed result's summary is FinishUP's own status line, not output:
                    # only the captured bytes it cites are.
                    bool(links.observed_output.get(str(ref)))
                    if target is recorded_observed
                    else _carries_output(row.payload)
                ):
                    target["output_results"].append((row.source_frontier, str(ref)))
    for row in projection.plans.values():
        if row.source_frontier > after and row.payload is not None and not row.redacted:
            recorded["plans"].append((row.source_frontier, str(row.source_event_id)))
    for row in projection.responses.values():
        if row.source_frontier > after and row.payload is not None and not row.redacted:
            recorded["responses"].append((row.source_frontier, str(row.source_event_id)))
    answers: list[dict[str | None, tuple[tuple[int, str], ...]]] = []
    for item in pending.items:
        candidates = tuple(
            entry
            for family in _ANSWERING_FAMILIES[item.kind]
            for entry in recorded[family]
            if entry[1] in allowed
        )
        if not item.target_refs:
            answers.append({None: candidates})
            continue
        candidates += tuple(
            entry
            for family in _ANSWERING_FAMILIES[item.kind]
            for entry in recorded_observed[family]
            if entry[1] in allowed
        )
        answers.append(
            {
                target: tuple(entry for entry in candidates if entry[1] in bound)
                for target in item.target_refs
                for bound in (links.answers(target),)
            }
        )
    return tuple(answers)


type _RunKey = tuple[str, str]


# A workspace-relative path, normalized, and whether it is certainly a path (``False`` for a
# bare single-segment reference such as ``Makefile`` or ``stdout``, which may be a path or a word).
type _Path = tuple[str, bool]
# The whole working tree (a bare ``git diff``) or the pathspecs a ``git diff`` names.
_WHOLE_TREE: Final = "."


@dataclass(frozen=True, slots=True)
class _Subject:
    """What a target names: its runs (actions and exact-command keys) and its file paths."""

    actions: frozenset[str]
    keys: frozenset[_RunKey]
    paths: frozenset[_Path]

    def __or__(self, other: _Subject) -> _Subject:
        return _Subject(
            self.actions | other.actions, self.keys | other.keys, self.paths | other.paths
        )

    def __bool__(self) -> bool:
        return bool(self.actions or self.keys or self.paths)


_NO_SUBJECT: Final = _Subject(frozenset(), frozenset(), frozenset())


@dataclass(frozen=True, slots=True)
class _Links:
    """Direct relations from a named target to agent material recorded after the request.

    Only new, agent-published, unredacted material counts; citing the old target again is not
    new material, and nothing spreads through other newer rows or shared obligations. For an
    action, result or evidence target, the answer is: a result of the named action or of another
    run of the same exact command (compared with whitespace collapsed; a hook run is identified by
    its ``omitted:<digest>`` and matches only the same digest, never ``omitted:structural``), and
    the new evidence such a result cites; a ``git diff`` run naming one of the target's paths and
    the evidence its result cites; and new evidence whose ``reference`` is the target's own id or
    one of its paths. A target's paths are its evidence ``reference`` when that is a file path,
    the paths a hook-captured edit records (supplied by the caller from the authenticated
    capture), and the paths of a ``git diff`` command behind it. Paths compare normalized but
    exact (see ``_normal_path``).

    W6 (ADR-006 amendment): a run's identity is its text and, with the installation key, the
    keyed identity a hook records for exactly that text (``_run_identities``), so an
    agent-published run and a hook-observed re-run of the same whole command are one command. A
    hook-observed re-run of a target's command after the request, its observed results and the
    captured output they cite, answer the target too (never paths: observed ``git diff`` text is
    not recorded and observed edits stay excluded). An evidence ``reference`` matches the target
    id or the target row's own event id, with surrounding whitespace ignored; an ``evt_`` target
    that names exactly one row's event is read as that row. The requesting check's own event id
    names the request, not a target, so it never matches. A claim is answered by material tied to
    what it cites; a correction (``claim_recorded`` 1.1.0 superseding it, or any claim disputing it) answers it,
    with the new material it cites when that is tied to the claim's support or the claim cited
    nothing FinishUP can relate. A finding is answered by a response to it and what that cites, a
    plan by the version that supersedes it, and an obligation by new actions, results, claims and
    plans that name it.
    """

    projection: ProjectionState
    after: int
    roots: frozenset[str]
    captured: Mapping[str, frozenset[_Path]]
    new_actions: Mapping[str, ActionRecordedPayload]
    new_results: Mapping[str, ResultRecordedPayload]
    new_evidence: Mapping[str, EvidenceRecordedPayload]
    new_claims: Mapping[str, ClaimRecordedPayload | ClaimRecordedPayloadV1_1]
    new_responses: Mapping[str, ResponseRecordedPayload]
    new_plans: Mapping[str, PlanPublishedPayload | PlanRevisedPayload]
    actions_by_key: Mapping[_RunKey, frozenset[str]]
    # Hook-observed command runs recorded after the request, with their identities; their
    # observed results; and the hook-captured evidence those results cite.
    observed_runs: Mapping[str, frozenset[_RunKey]]
    observed_results: Mapping[str, ResultRecordedPayload]
    observed_output: Mapping[str, frozenset[str]]
    # Each action, result, evidence, claim and obligation row's own event id.
    row_events: Mapping[str, str]
    request_event_id: str | None

    @classmethod
    def of(
        cls,
        projection: ProjectionState,
        after: int,
        observation_event_ids: frozenset[str],
        captured_edit_paths: Mapping[str, frozenset[str]],
        workspace_root: str | None,
        *,
        request_event_id: str | None = None,
    ) -> _Links:
        def observed(row: _Row) -> bool:
            return str(row.source_event_id) in observation_event_ids or _hook_observed(row.payload)

        def readable(row: _Row) -> bool:
            return row.source_frontier > after and row.payload is not None and not row.redacted

        def newer(row: _Row) -> bool:
            return readable(row) and not observed(row)

        by_key: dict[_RunKey, set[str]] = {}
        for ref, row in projection.actions.items():
            for key in _run_identities(row.payload):
                by_key.setdefault(key, set()).add(str(ref))
        observed_runs: dict[str, frozenset[_RunKey]] = {}
        for ref, row in projection.actions.items():
            payload = row.payload
            if (
                readable(row)
                and observed(row)
                and payload is not None
                and payload.action_kind is ActionKind.COMMAND
                and (identities := _run_identities(payload))
            ):
                observed_runs[str(ref)] = identities
        observed_results = {
            str(ref): row.payload
            for ref, row in projection.results.items()
            if readable(row)
            and observed(row)
            and row.payload is not None
            and str(row.payload.action_id) in observed_runs
        }
        # Only evidence holding captured bytes is output; a digest-only observed row is not.
        captured_output = {
            str(ref)
            for ref, row in projection.evidence.items()
            if readable(row)
            and observed(row)
            and row.payload is not None
            and row.payload.captured_object_id is not None
        }
        observed_output = {
            ref: frozenset(
                str(item) for item in result.evidence_refs if str(item) in captured_output
            )
            for ref, result in observed_results.items()
        }
        row_events: dict[str, str] = {}
        for rows in (
            projection.actions,
            projection.results,
            projection.evidence,
            projection.claims,
            projection.obligations,
        ):
            for ref, row in rows.items():
                row_events[str(ref)] = str(row.source_event_id)
        roots = _workspace_roots(workspace_root)
        captured = {
            ref: frozenset(
                path
                for raw in paths
                if (path := _normal_path(raw, roots, known_path=True)) is not None
                and path[0] != _WHOLE_TREE
            )
            for ref, paths in captured_edit_paths.items()
        }
        return cls(
            projection=projection,
            after=after,
            roots=roots,
            captured=captured,
            new_actions={
                str(ref): row.payload
                for ref, row in projection.actions.items()
                if newer(row) and row.payload is not None
            },
            new_results={
                str(ref): row.payload
                for ref, row in projection.results.items()
                if newer(row) and row.payload is not None
            },
            new_evidence={
                str(ref): row.payload
                for ref, row in projection.evidence.items()
                if newer(row) and row.payload is not None
            },
            new_claims={
                str(ref): row.payload
                for ref, row in projection.claims.items()
                if newer(row) and row.payload is not None
            },
            new_responses={
                str(row.source_event_id): row.payload
                for row in projection.responses.values()
                if newer(row) and row.payload is not None
            },
            new_plans={
                str(row.source_event_id): row.payload
                for row in projection.plans.values()
                if newer(row) and row.payload is not None
            },
            actions_by_key={key: frozenset(refs) for key, refs in by_key.items()},
            observed_runs=observed_runs,
            observed_results=observed_results,
            observed_output=observed_output,
            row_events=row_events,
            request_event_id=request_event_id,
        )

    def observed_material(self) -> frozenset[str]:
        """Every observed row that can answer a target: observed runs, results, their output."""

        return frozenset(
            {
                *self.observed_runs,
                *self.observed_results,
                *(ref for refs in self.observed_output.values() for ref in refs),
            }
        )

    def canonical(self, target: str) -> str:
        """The row id an ``evt_`` target names when it is exactly one row's own event id."""

        if not target.startswith("evt_") or target == self.request_event_id:
            return target
        rows = [ref for ref, event in self.row_events.items() if event == target]
        return rows[0] if len(rows) == 1 else target

    def aliases(self, target: str) -> frozenset[str]:
        """The ids that name ``target``'s record: its id and its own event id."""

        names = {target}
        event = self.row_events.get(target)
        if event is not None:
            names.add(event)
        return frozenset(names - {self.request_event_id})

    def answers(self, target: str) -> frozenset[str]:
        """The new material directly tied to ``target``."""

        target = self.canonical(target)
        names = self.aliases(target)
        found: set[str] = {
            ref
            for ref, evidence in self.new_evidence.items()
            if evidence.reference is not None and evidence.reference.strip() in names
        }
        projection = self.projection
        claim = next((row for ref, row in projection.claims.items() if str(ref) == target), None)
        if claim is not None:
            return frozenset(found | self._claim_answers(target, claim.payload))
        if any(str(ref) == target for ref in projection.findings):
            for ref, response in self.new_responses.items():
                if str(response.finding_id) == target:
                    found.add(ref)
                    found.update(self._new_cited(response.evidence_refs))
            return frozenset(found)
        if any(str(ref) == target for ref in projection.obligations):
            return frozenset(found | self._obligation_answers(target))
        plan_version = next(
            (
                version
                for version, row in projection.plans.items()
                if str(row.source_event_id) == target
            ),
            None,
        )
        if plan_version is not None:
            found.update(
                ref
                for ref, plan in self.new_plans.items()
                if type(plan) is PlanRevisedPayload and plan.supersedes_plan_version == plan_version
            )
            return frozenset(found)
        return frozenset(found | self._material(self.subject(target)))

    def _new_cited(self, refs: Iterable[object]) -> set[str]:
        return {
            str(ref)
            for ref in refs
            if str(ref) in self.new_evidence or str(ref) in self.new_results
        }

    def _action(self, ref: str) -> ActionRecordedPayload | None:
        row = next((item for key, item in self.projection.actions.items() if str(key) == ref), None)
        return None if row is None else row.payload

    def _wrote_artifact(self, action_ref: str) -> bool:
        """Whether the action is a command other than a ``git diff`` (its files are artifacts)."""

        action = self._action(action_ref)
        return (
            action is not None
            and action.action_kind is ActionKind.COMMAND
            and _diff_scope(action.command, self.roots) is None
        )

    def _evidence_paths(self, ref: str, *, artifact: bool) -> frozenset[_Path]:
        """A hook capture's recorded paths, and its ``reference`` unless a command wrote it."""

        paths = set(self.captured.get(ref, frozenset()))
        row = next(
            (item for key, item in self.projection.evidence.items() if str(key) == ref), None
        )
        if not artifact and row is not None and row.payload is not None:
            reference = row.payload.reference
            path = None if reference is None else _normal_path(reference, self.roots)
            if path is not None and path[0] != _WHOLE_TREE:
                paths.add(path)
        return frozenset(paths)

    def _action_subject(self, ref: str) -> _Subject:
        payload = self._action(ref)
        scope = None if payload is None else _diff_scope(payload.command, self.roots)
        paths: frozenset[_Path] = frozenset(
            (path, True) for path in (scope or ()) if path != _WHOLE_TREE
        )
        return _Subject(frozenset({ref}), _run_identities(payload), paths)

    def subject(self, target: str) -> _Subject:
        """The runs and paths an action, result or evidence target names (older rows only)."""

        projection = self.projection
        subject = _NO_SUBJECT
        if any(str(ref) == target for ref in projection.actions):
            subject = self._action_subject(target)
            artifact = self._wrote_artifact(target)
            for row in projection.results.values():
                if (
                    row.payload is not None
                    and row.source_frontier <= self.after
                    and str(row.payload.action_id) == target
                ):
                    for evidence_ref in row.payload.evidence_refs:
                        subject = subject | _Subject(
                            frozenset(),
                            frozenset(),
                            self._evidence_paths(str(evidence_ref), artifact=artifact),
                        )
            return subject
        result = next((row for ref, row in projection.results.items() if str(ref) == target), None)
        if result is not None:
            if result.payload is None:
                return subject
            action = str(result.payload.action_id)
            subject = self._action_subject(action)
            artifact = self._wrote_artifact(action)
            for evidence_ref in result.payload.evidence_refs:
                subject = subject | _Subject(
                    frozenset(),
                    frozenset(),
                    self._evidence_paths(str(evidence_ref), artifact=artifact),
                )
            return subject
        if any(str(ref) == target for ref in projection.evidence):
            artifact = False
            for row in projection.results.values():
                if (
                    row.payload is not None
                    and row.source_frontier <= self.after
                    and any(str(item) == target for item in row.payload.evidence_refs)
                ):
                    action = str(row.payload.action_id)
                    subject = subject | self._action_subject(action)
                    artifact = artifact or self._wrote_artifact(action)
            subject = subject | _Subject(
                frozenset(), frozenset(), self._evidence_paths(target, artifact=artifact)
            )
        return subject

    def _material(self, subject: _Subject) -> set[str]:
        """New actions, results and evidence tied to a subject's runs or paths.

        Path material answers only when, together, it covers every path the subject names: a
        diff of one file does not answer an edit that changed two.
        """

        if not subject:
            return set()
        runs = set(subject.actions)
        for key in subject.keys:
            runs.update(self.actions_by_key.get(key, frozenset()))
        wanted = {path for path, _certain in subject.paths}
        covering: dict[str, set[str]] = {}
        for ref, action in self.new_actions.items():
            scope = _diff_scope(action.command, self.roots)
            if scope is not None:
                covered = {path for path in wanted if any(_under(path, spec) for spec in scope)}
                if covered:
                    covering[ref] = covered
        for ref, evidence in self.new_evidence.items():
            reference = evidence.reference
            path = None if reference is None else _normal_path(reference, self.roots)
            if path is not None:
                covered = {
                    wanted_path
                    for wanted_path, certain in subject.paths
                    if wanted_path == path[0] and (certain or path[1])
                }
                if covered:
                    covering[ref] = covered
        by_path: set[str] = set()
        if wanted and set().union(*covering.values()) >= wanted:
            runs.update(ref for ref in covering if ref in self.new_actions)
            by_path = {ref for ref in covering if ref in self.new_evidence}
        found = {ref for ref in self.new_actions if ref in runs} | by_path
        for ref, result in self.new_results.items():
            cited = {str(item) for item in result.evidence_refs if str(item) in self.new_evidence}
            if str(result.action_id) in runs:
                found.add(ref)
                found |= cited
            elif cited & by_path:
                found.add(ref)
        # W6: a re-run of the same exact command FinishUP observed, with what it observed.
        observed = {ref for ref, keys in self.observed_runs.items() if keys & subject.keys}
        found |= observed
        for ref, result in self.observed_results.items():
            if str(result.action_id) in observed:
                found.add(ref)
                found |= self.observed_output.get(ref, frozenset())
        return found

    def _claim_answers(
        self, target: str, claim: ClaimRecordedPayload | ClaimRecordedPayloadV1_1 | None
    ) -> set[str]:
        support: tuple[object, ...] = ()
        if claim is not None:
            support = (
                *claim.supporting_refs,
                *(claim.limitation_refs if type(claim) is ClaimRecordedPayloadV1_1 else ()),
            )
        subject = _NO_SUBJECT
        for ref in support:
            subject = subject | self.subject(str(ref))
        found = self._material(subject)
        for ref, correction in self.new_claims.items():
            replaced = (
                correction.supersedes_claim_refs
                if type(correction) is ClaimRecordedPayloadV1_1
                else ()
            )
            if not any(str(item) == target for item in (*replaced, *correction.disputes_refs)):
                continue
            found.add(ref)
            cited = self._new_cited(
                (
                    *correction.supporting_refs,
                    *(
                        correction.limitation_refs
                        if type(correction) is ClaimRecordedPayloadV1_1
                        else ()
                    ),
                )
            )
            # A claim that cited nothing FinishUP can relate is answered by what its correction
            # cites; otherwise only cited material tied to the claim's own support counts.
            found |= cited if not subject else cited & found
        return found

    def _obligation_answers(self, target: str) -> set[str]:
        found = {
            ref
            for ref, action in self.new_actions.items()
            if any(str(item) == target for item in action.obligation_refs)
        }
        for ref, result in self.new_results.items():
            if str(result.action_id) in found:
                found.add(ref)
                found |= {
                    str(item) for item in result.evidence_refs if str(item) in self.new_evidence
                }
        found |= {
            ref
            for ref, claim in self.new_claims.items()
            if any(str(item) == target for item in claim.obligation_refs)
        }
        for ref, plan in self.new_plans.items():
            named = (
                plan.obligation_refs
                if type(plan) is PlanPublishedPayload
                else tuple(
                    item
                    for change in cast(PlanRevisedPayload, plan).obligation_changes
                    for item in (change.obligation_id, *change.replacement_obligation_ids)
                )
            )
            if any(str(item) == target for item in named):
                found.add(ref)
        return found


class _Row(Protocol):
    @property
    def payload(self) -> object | None: ...
    @property
    def redacted(self) -> bool: ...
    @property
    def source_event_id(self) -> EventId: ...
    @property
    def source_frontier(self) -> int: ...


def _run_key(payload: ActionRecordedPayload | None) -> _RunKey | None:
    """What makes two runs the same command: its text with whitespace collapsed.

    A hook records ``omitted:<digest>`` instead of the text; the same digest is the same command
    text, so it matches only that digest. ``omitted:structural`` identifies nothing. A composed
    run also carries a segment suffix (``omitted:<identity> <composition> <segment>...``, #988);
    only the leading identity keys it, so one command recorded before and after that suffix
    existed is one run.
    """

    if payload is None or payload.command is None:
        return None
    command = " ".join(payload.command.split())
    if command.startswith("omitted:"):
        digest = command.removeprefix("omitted:").split(" ", 1)[0]
        return None if digest in {"", "structural"} else ("digest", digest)
    return ("command", command) if command else None


def _run_identities(payload: ActionRecordedPayload | None) -> frozenset[_RunKey]:
    """``_run_key`` plus, for command text, the keyed identity a hook records for exactly it.

    Supply judgement only: an agent-published run and a hook-observed re-run of the same exact
    command are one command. Whole commands only (``cd x && pytest`` is not ``pytest``). Without
    the installation key only ``_run_key`` applies, so a process that cannot compute the identity
    never claims two runs are the same.
    """

    key = _run_key(payload)
    if key is None:
        return frozenset()
    keys = {key}
    if key[0] == "command" and payload is not None and payload.command is not None:
        keyed = requested_command_identity(payload.command)
        if keyed is not None:
            keys.add(("digest", keyed))
    return frozenset(keys)


def command_run_key(payload: ActionRecordedPayload | None) -> tuple[str, str] | None:
    """What makes two recorded runs the same command (see ``_run_key``), for packet selection.

    Shared with the review packet's latest-run rule (issue #1045), so "the same probe" means the
    same thing when the packet keeps the newest run as when a missing-item request is answered.
    """

    return _run_key(payload)


def _workspace_roots(workspace_root: str | None) -> frozenset[str]:
    """The workspace root as given and, when it exists, as ``realpath`` resolves it.

    This is the module's only filesystem access: the root the session opened with, never a path an
    agent named. Both spellings let ``/tmp/w/a.py`` and ``/private/tmp/w/a.py`` name one file.
    """

    if workspace_root is None or not os.path.isabs(workspace_root):
        return frozenset()
    given = os.path.normpath(workspace_root)
    roots = {given}
    if os.path.isdir(given):
        roots.add(os.path.realpath(given))
    return frozenset(roots - {"/"})


def _normal_path(text: str, roots: frozenset[str], *, known_path: bool = False) -> _Path | None:
    """A workspace-relative path, normalized but exact; ``None`` when it is not one.

    Surrounding whitespace, ``./`` and ``.`` segments, repeated and trailing slashes are dropped;
    case and every other character are kept, and ``..`` is never resolved. An absolute path counts
    only inside the workspace root (as given or as it resolves), compared lexically after
    ``os.path.normpath`` and never resolved on the filesystem, as the path relative to it; the
    root itself is the whole tree (``.``). A single segment with no slash is
    not certainly a path (``Makefile`` or ``stdout``) unless ``known_path`` says so (a captured
    edit's path, a ``git diff`` argument); it then matches only a certain path.
    """

    text = text.strip()
    if not text or any(char.isspace() for char in text) or "://" in text:
        return None
    if text.startswith("/"):
        relative = _inside(os.path.normpath(text), roots)
        return None if relative is None else (relative, True)
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if not parts:
        return (_WHOLE_TREE, True)
    name = parts[-1]
    certain = (
        known_path
        or "/" in text
        or len(parts) > 1
        or (not name.startswith(".") and "." in name[1:])
    )
    return ("/".join(parts), certain)


def _inside(path: str, roots: frozenset[str]) -> str | None:
    for root in roots:
        if path == root:
            return _WHOLE_TREE
        if path.startswith(root + "/"):
            return path.removeprefix(root + "/")
    return None


def _under(path: str, spec: str) -> bool:
    """Whether a ``git diff`` pathspec covers a path: the whole tree, the path, or a parent."""

    return spec == _WHOLE_TREE or path == spec or path.startswith(spec + "/")


# ``git diff`` options that print no file content, so the run cannot answer a content request.
_SUMMARY_DIFF_OPTIONS: Final = frozenset(
    {
        "--name-only",
        "--name-status",
        "--numstat",
        "--shortstat",
        "--summary",
        "--quiet",
        "--raw",
        "--no-patch",
        "-s",
        "--check",
    }
)
_REVISION: Final = re.compile(
    r"(?:HEAD|FETCH_HEAD|ORIG_HEAD|MERGE_HEAD|@)(?:[~^][0-9]*)*|[0-9a-f]{7,40}|.*\.\..*"
)


def _diff_scope(command: str | None, roots: frozenset[str]) -> frozenset[str] | None:
    """The workspace-relative pathspecs a content ``git diff`` covers; ``None`` for anything else.

    Recognized: ``git [--no-pager] [-C <workspace root>] diff [options] [revisions] [--]
    [paths]``. No path, or ``.``, is the whole tree (``.``). A summary form (``--stat``,
    ``--name-only``, ``--numstat`` and the like) prints no content and is not recognized, nor is
    ``-C`` naming any other directory. Revisions are ``HEAD``-style names, commit ids and
    ``a..b`` ranges; any other word before ``--`` is read as a path.
    """

    if command is None:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if len(tokens) < 2 or tokens[0] != "git":
        return None
    index = 1
    while index < len(tokens) and tokens[index] != "diff":
        token = tokens[index]
        if token == "--no-pager":
            index += 1
        elif token == "-C" and index + 1 < len(tokens):
            directory = _normal_path(tokens[index + 1], roots, known_path=True)
            if directory is None or directory[0] != _WHOLE_TREE:
                return None
            index += 2
        else:
            return None
    if index >= len(tokens):
        return None
    specs: set[str] = set()
    literal = False
    for token in tokens[index + 1 :]:
        if token in {"&&", "||", "|", ";", ">", ">>"}:
            break
        if not literal and token == "--":
            literal = True
            continue
        if not literal and token.startswith("-"):
            if token in _SUMMARY_DIFF_OPTIONS or token.startswith(("--stat", "--dirstat")):
                return None
            continue
        if not literal and _REVISION.fullmatch(token):
            continue
        path = _normal_path(token, roots, known_path=True)
        if path is None:
            return None
        specs.add(path[0])
    return frozenset(specs or {_WHOLE_TREE})


def _carries_output(payload: ResultRecordedPayload) -> bool:
    return bool(payload.evidence_refs) or bool(payload.summary and payload.summary.strip())


def _hook_observed(payload: object) -> bool:
    """Hook-captured bytes carry service-stamped observation provenance on their evidence row."""

    return (
        type(payload) is EvidenceRecordedPayload
        and payload.digest_binding is not None
        and payload.digest_binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
    )


def _redacted_refs(projection: ProjectionState) -> frozenset[str]:
    redacted: set[str] = set()
    for rows in (
        projection.obligations,
        projection.actions,
        projection.results,
        projection.evidence,
        projection.claims,
        projection.findings,
    ):
        for ref, row in rows.items():
            if row.redacted:
                redacted.update((str(ref), str(row.source_event_id)))
    return frozenset(redacted)


def review_missing_for_assessment(
    case: DeterministicCase,
    deterministic: tuple[Finding, ...],
    judgment: SemanticJudgment,
    *,
    unsuppliable_kinds: frozenset[str],
    citable_refs: frozenset[str] | None = None,
    captured_edit_paths: Mapping[str, frozenset[str]] | None = None,
    workspace_root: str | None = None,
    packet_limited_refs: frozenset[str] = frozenset(),
    privacy_withheld_refs: frozenset[str] = frozenset(),
    change_clipped: bool = False,
    binary_paths: frozenset[str] = frozenset(),
    text_paths: frozenset[str] = frozenset(),
    excerpt_refs: frozenset[str] | None = None,
    excerpt_parts: frozenset[str] | None = None,
) -> MissingItemsReview:
    """Fence what the reviewer named to the packet it was shown and classify who can supply it.

    A target outside the packet's ``citable_refs`` (the frozen case when the composing evaluator
    did not report the packet) is dropped (``semantic_missing_items_rejected``), as #905 trims a
    ruling's cited refs; an item whose every target was outside is dropped whole, because the
    reviewer named nothing the packet held.
    An ``insufficient_packet`` that named no item at all discloses the same gap.
    An item the prior review already requested and the agent answered since, target by target,
    is dropped unless the reviewer cites that newer material
    (``semantic_missing_already_supplied``), so the same request cannot loop; only new material
    directly tied to a target answers it (see ``_Links``; ``captured_edit_paths`` as in
    ``supplied_since``). A hook-observed re-run answers only when this packet carried it (W6,
    ADR-006 amendment): its run and result rows among the citable refs, and for
    ``verification_output`` the captured output its result cites among the excerpts the sent
    packet held (``excerpt_refs`` whole, or any of its ``excerpt_parts``; ``None``: unknown, so
    nothing observed was carried). Every kept item is recorded with FinishUP's own availability
    class.

    Content the packet cannot show is FinishUP's own limit, never agent work (tb4n1 D1, #983): a
    target whose recorded file is an image or other binary format, by suffix or because the
    check-time change marks it binary (``binary_paths``, see ``check_change_binary_paths``)
    (``yoetz_limit_unsupported_data_type``); a target the packet named but could not carry whole
    (``packet_limited_refs``), or a diff request while the check-time change's own text was
    clipped for room or redacted (``change_clipped``; a redacted task input file alone is not,
    when the shown-file record is complete and names a file) (``yoetz_limit_packet_room``). The agent verifies such content itself;
    the receipt discloses the limit. An unanswered repeat stays the agent's work with
    ``semantic_missing_non_convergent``; the review round itself stops after one retry
    (``kernel.review_round``).
    """

    if judgment.conclusion != "insufficient_packet":
        return MissingItemsReview((), frozenset())
    if not judgment.missing_for_assessment:
        # A reply in the 1.0.0 shape (a local model or prompt-only host) named nothing: the agent
        # cannot tell what to supply, so the check says so instead of reading as a named request.
        return MissingItemsReview((), frozenset({SEMANTIC_MISSING_ITEMS_REJECTED_GAP}))
    allowed = frozenset(str(ref) for ref in case.allowed_ids) | frozenset(
        str(item.finding_id) for item in deterministic
    )
    projection = case.projection
    pending = projection.pending_missing_for_assessment
    observed = frozenset(str(item) for item in case.observation_event_ids)
    answered = (
        ()
        if pending is None
        else _answers_by_target(
            projection, pending, allowed, observed, captured_edit_paths, workspace_root
        )
    )
    redacted = _redacted_refs(projection)
    shown = allowed if citable_refs is None else allowed & citable_refs
    if pending is not None:
        # W6: never drop a repeat as already supplied for observed material the reviewer could
        # not see; the item then stays the agent's under the rules below.
        unseen, unseen_output = _unseen_observed(
            _Links.of(
                projection,
                pending.source_frontier,
                observed,
                captured_edit_paths or {},
                workspace_root,
                request_event_id=str(pending.source_check_event_id),
            ),
            shown,
            _carried_excerpts(excerpt_refs, excerpt_parts),
        )
        answered = tuple(
            {
                target: tuple(
                    entry
                    for entry in entries
                    if entry[1]
                    not in (unseen_output if prior.kind == "verification_output" else unseen)
                )
                for target, entries in per_target.items()
            }
            for prior, per_target in zip(pending.items, answered, strict=True)
        )
    paths_of = _TargetFiles(
        _Links.of(projection, _ALL_ROWS, observed, captured_edit_paths or {}, workspace_root),
        captured_edit_paths or {},
        binary_paths,
        text_paths,
    )
    gaps: set[str] = set()
    kept: dict[tuple[str, tuple[str, ...]], str] = {}
    for entry in judgment.missing_for_assessment:
        refs = tuple(ref for ref in entry.target_refs if ref in shown)
        if len(refs) != len(entry.target_refs):
            gaps.add(SEMANTIC_MISSING_ITEMS_REJECTED_GAP)
            if not refs:
                continue
        matching_prior = (
            ()
            if pending is None
            else tuple(
                (prior, prior_answers)
                for prior, prior_answers in zip(pending.items, answered, strict=True)
                if prior.kind == entry.kind
                and (
                    (not refs and not prior.target_refs)
                    or (bool(refs) and set(refs) <= set(prior.target_refs))
                )
            )
        )
        if any(_answered(prior, prior_answers, refs) for prior, prior_answers in matching_prior):
            gaps.add(SEMANTIC_MISSING_ALREADY_SUPPLIED_GAP)
            continue
        availability = (
            STRUCTURALLY_UNAVAILABLE
            if entry.kind in unsuppliable_kinds or set(refs) & (redacted | privacy_withheld_refs)
            else _finishup_limit(
                entry.kind,
                refs,
                paths_of,
                packet_limited_refs=packet_limited_refs,
                change_clipped=change_clipped,
            )
        )
        if matching_prior and availability == AGENT_SUPPLIABLE:
            # The reviewer named only an earlier target set and no directly related publication
            # answered it. It stays the agent's work (a run never recorded is still owed), with
            # the non-convergent disclosure; the review round itself stops after the one retry
            # (``review_round_stopped``, tb4n1 D3). A genuinely new target is intentionally
            # excluded by the subset test above.
            gaps.add(SEMANTIC_MISSING_NON_CONVERGENT_GAP)
        key = (entry.kind, refs)
        if kept.get(key, AGENT_SUPPLIABLE) == AGENT_SUPPLIABLE:
            kept[key] = availability
    items = tuple(
        MissingForAssessmentItem(kind=kind, target_refs=refs, availability=availability)
        for (kind, refs), availability in sorted(
            kept.items(),
            key=lambda pair: (
                pair[0][0].encode("ascii"),
                tuple(ref.encode("ascii") for ref in pair[0][1]),
            ),
        )
    )
    for item in items:
        gaps.add(
            SEMANTIC_MISSING_AGENT_SUPPLIABLE_GAP
            if item.availability == AGENT_SUPPLIABLE
            else SEMANTIC_MISSING_UNAVAILABLE_GAP
            if item.availability == STRUCTURALLY_UNAVAILABLE
            else SEMANTIC_MISSING_FINISHUP_LIMIT_GAP
        )
    return MissingItemsReview(items, frozenset(gaps))


def _carried_excerpts(
    excerpt_refs: frozenset[str] | None, excerpt_parts: frozenset[str] | None
) -> frozenset[str]:
    """The refs a sent packet's excerpts held, whole or in part (a marked observed span too)."""

    carried = set(excerpt_refs or ())
    for key in excerpt_parts or ():
        span = _span(key)
        if span is not None:
            carried.add(span[0].removeprefix(OBSERVED_COMMAND_OUTPUT_SPAN_PREFIX))
    return frozenset(carried)


def _unseen_observed(
    links: _Links, shown: frozenset[str], carried: frozenset[str]
) -> tuple[frozenset[str], frozenset[str]]:
    """Observed refs a packet did not carry: for any kind, and for ``verification_output``.

    A run or result row is carried when it was citable; captured output only when an excerpt
    held its bytes. For ``verification_output`` an observed result also needs some captured
    output it cites carried, because the output is what was asked for.
    """

    output = frozenset(ref for refs in links.observed_output.values() for ref in refs)
    unseen = {ref for ref in links.observed_material() if ref not in shown}
    unseen.update(ref for ref in output if ref not in carried)
    unseen_output = set(unseen)
    unseen_output.update(
        ref
        for ref, cited in links.observed_output.items()
        if not any(item in carried and item in shown for item in cited)
    )
    return frozenset(unseen), frozenset(unseen_output)


# Read every recorded row as "older" when only a target's files are wanted, never its answers.
_ALL_ROWS: Final = 2**62


@dataclass(frozen=True, slots=True)
class _TargetFiles:
    """The file names a target records: evidence references and captured edit paths.

    Used only to recognise content the packet never carries by its file type; the names are
    compared lexically and never resolved or opened.
    """

    links: _Links
    captured: Mapping[str, frozenset[str]]
    # Workspace-relative paths the check-time change marks binary (tb4n2 A11).
    binary: frozenset[str] = frozenset()
    # Workspace-relative paths the same change lists as text (ADR-045): Git's NUL sniff found no
    # NUL byte, so their suffix says nothing (a ``.step`` file is ASCII).
    text: frozenset[str] = frozenset()

    def _relative(self, name: str) -> str | None:
        path = _normal_path(name, self.links.roots, known_path=True)
        if path is not None:
            return path[0]
        if name.strip() and "://" not in name:
            # ``_normal_path`` refuses inner whitespace (prose is not a path), but Git names a
            # binary ``my solver`` exactly; an exact match against Git's own list is safe.
            text = name.strip()
            return (
                _inside(os.path.normpath(text), self.links.roots)
                if text.startswith("/")
                else "/".join(part for part in text.split("/") if part not in {"", "."})
            )
        return None

    def unsupported(self, name: str) -> bool:
        """Whether a recorded file name is a type the packet never carries.

        Git's own NUL sniff decides first (ADR-045): the check-time change found the file binary
        (a suffix-less ``solver`` or firmware blob) or found it text (a ``.step`` file). Only a
        file the change did not list falls back to its suffix. An absolute name counts only
        inside the workspace root; names compare normalized but exact, never resolved.
        """

        if self.binary or self.text:
            relative = self._relative(name)
            if relative is not None:
                if relative in self.binary:
                    return True
                if relative in self.text:
                    return False
        return _unsupported_data_type(name)

    def __call__(self, target: str) -> frozenset[str]:
        projection = self.links.projection
        # An ``evt_`` target names the event that recorded a row; resolve it to that row's own
        # id, and read the file names any plan, task statement or obligation text mentions.
        refs = {target}
        names: set[str] = set()
        for family in (
            projection.actions,
            projection.results,
            projection.evidence,
            projection.claims,
            projection.obligations,
        ):
            for key, row in family.items():
                if str(row.source_event_id) == target:
                    refs.add(str(key))
        for ref in tuple(refs):
            names.update(path for path, _certain in self.links.subject(ref).paths)
            names.update(self.captured.get(ref, frozenset()))
            names.update(self._evidence_names(ref))
        return frozenset(name for name in names if name)

    def requested_files(self, target: str) -> frozenset[str] | None:
        """The requested output files in scope of a plan, statement or obligation target.

        Used only for an ``other`` item (a requirement the reviewer could not see, such as
        cad-model's "the schematic itself is unavailable"). An obligation target scopes its own
        requested ``file`` items; a plan or statement target scopes every effective obligation's.
        ``None`` when the target is none of these. Items the agent marked as inputs never count.
        Prose is never scanned: a file a statement only mentions may be an input.
        """

        projection = self.links.projection
        obligations = [
            row
            for key, row in projection.obligations.items()
            if target in {str(key), str(row.source_event_id)}
        ]
        if not obligations:
            if not any(str(row.source_event_id) == target for row in projection.plans.values()):
                return None
            obligations = [projection.obligations[key] for key in effective_obligations(projection)]
        return frozenset(
            item.value
            for row in obligations
            if row.payload is not None and not row.redacted
            for item in row.payload.requested_items
            if getattr(item.item_kind, "value", item.item_kind) == "file"
            and item_role(item) != "input"
        )

    def _evidence_names(self, target: str) -> set[str]:
        names: set[str] = set()
        projection = self.links.projection
        evidence_refs = {target}
        for row in projection.results.values():
            payload = row.payload
            if payload is not None and target in {
                str(payload.action_id),
                *(str(ref) for ref in payload.evidence_refs),
            }:
                evidence_refs.update(str(ref) for ref in payload.evidence_refs)
        for ref, row in projection.evidence.items():
            if str(ref) in evidence_refs and row.payload is not None and not row.redacted:
                reference = row.payload.reference
                if reference is not None and "://" not in reference:
                    names.add(reference.strip())
                names.update(self.captured.get(str(ref), frozenset()))
        return names

    def observed_image(self, target: str) -> bool:
        """Whether the target is, or cites, a hook-observed image kept as a digest only.

        A host image tool result is recorded as service-stamped ``artifact_bytes`` evidence with
        ``digest_only`` availability (L3 P3-2): its pixels never reach the packet, so a reviewer
        request for it is an unsupported data type, never agent work.
        """

        projection = self.links.projection
        refs = {target}
        for row in projection.results.values():
            payload = row.payload
            if payload is not None and str(payload.action_id) == target:
                refs.update(str(ref) for ref in payload.evidence_refs)
        return any(
            str(ref) in refs and observed_image_evidence(row.payload)
            for ref, row in projection.evidence.items()
        )


def observed_image_evidence(payload: object) -> bool:
    """Whether an evidence payload is a hook-observed image kept as a digest only (L3 P3-2)."""

    if type(payload) is not EvidenceRecordedPayload:
        return False
    binding = payload.digest_binding
    return (
        binding is not None
        and binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
        and binding.subject is EvidenceDigestSubject.ARTIFACT_BYTES
        and binding.content_availability is not EvidenceContentAvailability.CAPTURED
        and (payload.description or "").startswith("Observed image")
    )


def unsupported_data_type(name: str) -> bool:
    """Whether a recorded file name is a type the review packet never carries (by suffix)."""

    return _unsupported_data_type(name)


# The rendered check-time change (``adapters.git_change_capture``): a header listing each changed
# file as ``  <status> <path>[ (binary)][ notes]``, then a unified diff whose binary sections carry
# Git's ``Binary files a/X and b/Y differ`` line (an untracked file FinishUP found NUL bytes in is
# rendered the same way against ``/dev/null``).
_CHANGE_HEADER_END: Final = b"\nEnd of header. The unified diff follows.\n"
_CHANGE_LISTED_BINARY: Final = re.compile(r"^  [A-Z?]+ (\S.*?) \(binary\)(?: .*)?$")
_CHANGE_BINARY_LINE: Final = re.compile(rb"^Binary files (.+) differ$", re.MULTILINE)


# A listed text entry: ``  <status> <path> (+<added> -<removed>)``. Git prints numeric line counts
# only for a file its NUL-byte heuristic found text; a binary file reads ``(binary)`` and a file
# whose counts were withheld or unknown prints none, which proves nothing either way.
_CHANGE_LISTED: Final = re.compile(r"^  [A-Z?]+ (\S.*?) \(\+[0-9]+ -[0-9]+\)(?: .*)?$")


def check_change_text_paths(capture: CheckChangeCapture | None) -> frozenset[str]:
    """The repository-relative paths the check-time change lists as text (ADR-045).

    The header lists each changed file once, with ``(binary)`` when Git's NUL-byte heuristic
    found it binary. Every other listed file was sniffed as text, so its suffix is no evidence:
    ``part.step`` (ISO 10303-21, ASCII) is reviewable. A quoted, cut-short or non-UTF-8 name is
    skipped, as for ``check_change_binary_paths``; a skipped name falls back to its suffix.
    """

    if capture is None:
        return frozenset()
    text = capture.text
    end = text.find(_CHANGE_HEADER_END)
    header = text if end < 0 else text[:end]
    binary = check_change_binary_paths(capture)
    paths: set[str] = set()
    for line in header.decode("utf-8", errors="replace").split("\n"):
        if _CHANGE_LISTED_BINARY.match(line) is not None:
            continue
        match = _CHANGE_LISTED.match(line)
        if match is None:
            continue
        listed = match.group(1)
        if listed.startswith('"'):
            unquoted = _git_unquote(listed)
            if unquoted is None or unquoted[1] != len(listed):
                continue
            listed = unquoted[0]
        if listed and not listed.endswith("...") and "\ufffd" not in listed:
            paths.add(listed)
    return frozenset(paths - binary)


def check_change_binary_paths(capture: CheckChangeCapture | None) -> frozenset[str]:
    """The repository-relative paths the check-time change marks binary (tb4n2 A11).

    Lets a suffix-less binary (a compiled ``solver``, ``a.out``, a firmware blob) count as a type
    the packet never carries, without the classifier reading any file: Git's NUL-byte heuristic
    already ran when the change was captured. Read from the header's ``(binary)`` entries and the
    diff's ``Binary files`` lines. A C-quoted path (non-ASCII or control bytes) is decoded the way
    Git encoded it; a malformed quote, or a path the header cut short, is skipped rather than
    guessed, so it stays classified by its suffix alone.
    """

    if capture is None:
        return frozenset()
    text = capture.text
    end = text.find(_CHANGE_HEADER_END)
    header = text if end < 0 else text[:end]
    paths: set[str] = set()
    for line in header.decode("utf-8", errors="replace").split("\n"):
        match = _CHANGE_LISTED_BINARY.match(line)
        if match is not None:
            listed = match.group(1)
            if listed.startswith('"'):
                unquoted = _git_unquote(listed)
                if unquoted is not None and unquoted[1] == len(listed):
                    paths.add(unquoted[0])
            else:
                paths.add(listed)
    if end >= 0:
        for match in _CHANGE_BINARY_LINE.finditer(text, end):
            paths.update(_binary_line_paths(match.group(1).decode("utf-8", errors="replace")))
    return frozenset(
        path
        for path in paths
        if path and not path.startswith('"') and not path.endswith("...") and "\ufffd" not in path
    )


_GIT_ESCAPES: Final[Mapping[str, int]] = {
    "a": 7,
    "b": 8,
    "t": 9,
    "n": 10,
    "v": 11,
    "f": 12,
    "r": 13,
    '"': 34,
    "\\": 92,
}


def _git_unquote(text: str) -> tuple[str, int] | None:
    """Decode one C-quoted Git path at the start of ``text``: ``(path, characters consumed)``.

    ``core.quotePath=true`` (which the capture forces) quotes a non-ASCII or control-byte name as
    ``"r\\303\\251sum\\303\\251"``. ``None`` when the quoting is malformed or the bytes are not
    UTF-8, so such a name stays classified by its suffix alone.
    """

    if not text.startswith('"'):
        return None
    raw = bytearray()
    index = 1
    while index < len(text):
        char = text[index]
        if char == '"':
            try:
                return raw.decode("utf-8"), index + 1
            except UnicodeDecodeError:
                return None
        if char != "\\":
            raw.extend(char.encode("utf-8"))
            index += 1
            continue
        escape = text[index + 1 : index + 2]
        if escape in _GIT_ESCAPES:
            raw.append(_GIT_ESCAPES[escape])
            index += 2
            continue
        octal = text[index + 1 : index + 4]
        if len(octal) == 3 and all(digit in "01234567" for digit in octal):
            raw.append(int(octal, 8) & 0xFF)
            index += 4
            continue
        return None
    return None


def _quoted_binary_line_paths(operands: str) -> tuple[str, ...] | None:
    """The paths of a ``Binary files`` line where Git quoted at least one operand; else ``None``."""

    if '"' not in operands:
        return None
    values: list[str] = []
    rest = operands
    for position in range(2):
        if rest.startswith('"'):
            decoded = _git_unquote(rest)
            if decoded is None:
                return ()
            value, consumed = decoded
            rest = rest[consumed:]
        else:
            cut = rest.find(" and ") if position == 0 else len(rest)
            if cut < 0:
                return ()
            value, rest = rest[:cut], rest[cut:]
        values.append(value)
        if position == 0:
            if not rest.startswith(" and "):
                return ()
            rest = rest[len(" and ") :]
    if rest:
        return ()
    paths = tuple(
        value[2:]
        for value, prefix in zip(values, ("a/", "b/"), strict=True)
        if value != "/dev/null" and value.startswith(prefix)
    )
    return paths


def _binary_line_paths(operands: str) -> tuple[str, ...]:
    """The paths of one ``Binary files <a> and <b>`` line; empty when it cannot be split surely.

    An unquoted path may itself hold `` and b/``, so a two-sided line is split only where both
    operands name the same path, or where exactly one split exists. A quoted operand (a
    non-ASCII or control-byte name) is decoded the way Git encoded it.
    """

    quoted = _quoted_binary_line_paths(operands)
    if quoted is not None:
        return quoted
    if operands.startswith("/dev/null and b/"):
        return (operands.removeprefix("/dev/null and b/"),)
    if operands.startswith("a/") and operands.endswith(" and /dev/null"):
        return (operands.removeprefix("a/").removesuffix(" and /dev/null"),)
    if not operands.startswith("a/"):
        return ()
    splits = [
        (operands[2:index], operands[index + len(" and b/") :])
        for index in range(len(operands))
        if operands.startswith(" and b/", index)
    ]
    same = [left for left, right in splits if left == right]
    if same:
        return (same[0],)
    return splits[0] if len(splits) == 1 else ()


def _unsupported_data_type(name: str) -> bool:
    base = name.rstrip("/").rsplit("/", 1)[-1].lower()
    dot = base.rfind(".")
    return dot > 0 and base[dot:] in _UNSUPPORTED_SUFFIXES


def _only_unsupported_outputs(refs: tuple[str, ...], paths_of: _TargetFiles) -> bool:
    """Every requested output file in the targets' scope is a type the packet never carries.

    One text deliverable in scope (missing or unshown) keeps the item the agent's work: the
    reviewer may be asking for exactly that file (satb's unwritten score, an unwritten script).
    """

    scoped = [files for ref in refs if (files := paths_of.requested_files(ref)) is not None]
    names = {name for files in scoped for name in files}
    return bool(names) and all(paths_of.unsupported(name) for name in names)


def _finishup_limit(
    kind: str,
    refs: tuple[str, ...],
    paths_of: _TargetFiles,
    *,
    packet_limited_refs: frozenset[str],
    change_clipped: bool,
) -> str:
    """Whether FinishUP's own packet, not the agent, is why the reviewer could not see the item."""

    if (
        any(paths_of.unsupported(name) for ref in refs for name in paths_of(ref))
        or any(paths_of.observed_image(ref) for ref in refs)
        or (kind == "other" and _only_unsupported_outputs(refs, paths_of))
    ):
        return FINISHUP_LIMIT_UNSUPPORTED_DATA_TYPE
    if set(refs) & packet_limited_refs:
        return FINISHUP_LIMIT_PACKET_ROOM
    if kind == "current_diff_for_path" and change_clipped:
        return FINISHUP_LIMIT_PACKET_ROOM
    return AGENT_SUPPLIABLE


def _answered(
    prior: MissingForAssessmentItem,
    per_target: Mapping[str | None, tuple[tuple[int, str], ...]],
    refs: tuple[str, ...],
) -> bool:
    """Whether the prior request named every one of ``refs`` and each was answered since.

    An untargeted repeat of an untargeted request is answered by any material of its kind. A
    target the prior request did not name is a new request; a repeat that cites the newer
    material says it is still insufficient, so neither is dropped.
    """

    if not refs:
        return not prior.target_refs and bool(per_target.get(None))
    supplied = {ref for entries in per_target.values() for _order, ref in entries}
    return (
        set(refs) <= set(prior.target_refs)
        and all(per_target.get(ref) for ref in refs)
        and not supplied & set(refs)
    )
