# Reviewer instruction evaluation runbook

Use this runbook when you change `SEMANTIC_REVIEW_INSTRUCTION`, `REVIEWER_LOOP_INSTRUCTION`, a lens,
the grounding rules, the review-phase questions or the acknowledged-obligation question. It checks
the instructions against the reviewer misses the N6 D-lane audit investigated (issue #1082), the n7
misses (issue #1108) and the TB4 full-sol misses (issue #1245). The design and the reasons are in
[ADR-006](../adr/ADR-006-semantic-provider-profile.md), "The reviewer instruction as a procedure
with named lenses" and "Observed witnesses, one reading of disclosure, primary material first".

## Run the offline check

The offline check makes no provider call and needs no service:

```text
uv run pytest tests/unit/adapters/providers/test_reviewer_accuracy_directives.py \
  tests/unit/adapters/providers/test_reviewer_accuracy_directives_n7.py \
  tests/unit/adapters/providers/test_reviewer_accuracy_directives_tb4_full.py \
  tests/unit/application/test_reviewer_loop.py \
  tests/unit/adapters/providers/test_reviewer_instruction.py \
  tests/unit/adapters/providers/test_task_statement_instruction.py -q
```

When the change also moves packet order, labels or excerpt room, add the packet tests:

```text
uv run pytest tests/unit/application/test_semantic_case.py \
  tests/unit/application/test_semantic_case_packet_completeness.py \
  tests/unit/application/test_semantic_case_check_change.py \
  tests/unit/application/test_semantic_case_prior_findings.py \
  tests/unit/application/test_review_packet_row_contract.py \
  tests/unit/application/test_native_verification_follow_up.py \
  tests/unit/application/test_review_follow_up.py -q
```

It fails when:

- a case no longer names a lens or section that targets its miss;
- a directive sentence a case relies on moved out of its lens or section, or was reworded;
- a lens lost its failure example, or the procedure no longer precedes the reference material;
- the instruction names an evaluation case or its domain words, which would fit the instruction to
  the evaluation set.

A failure here is a decision, not a chore. When you reword a directive on purpose, update the
case in `tests/fixtures/reviewer_accuracy/n6_cases.json`, `n7_cases.json` or
`tb4_full_cases.json` and say in the pull
request why the new wording still targets that miss. The n7 test also checks that every N6
directive still holds.

## The checklist

Each row is one investigated miss, the lens or section that targets it, and the directive the
fixture pins. "Detectable" says whether the decisive material was in the packet the reviewer saw.

| Case | Detectable | Miss | Lens or section | Directive (short form) |
| --- | --- | --- | --- | --- |
| atrx-vep-crispr | yes | adopted the agent's premise | premise, numbers, blockers, earlier findings | A task-defined reference, unit or version is the one every result uses; a shared name is not identity. A newly found reasoning error is a new problem, not a re-raise. |
| batched-eval-parity | yes | boundary not tested | boundaries, own checks | Decide what is counted and when the bound is tested; trace below, at and above it; a probe count is not a boundary witness. |
| biped-contact-dynamics | partly | trusted the agent's validator | own checks, boundaries | Treat the agent's checks as claims; confirm the measured quantity, window, exclusions, aggregation and threshold match the requirement. |
| cargo-flight-dispatch | partly | adopted the agent's premise | blockers, premise, numbers | List each constraint an infeasibility argument relies on, find the task text for it, and recompute under the strongest permitted reading. |
| foodstuff-beta-activity | yes | insufficient packet hid a visible defect | numbers, missing content | An implausible number is a challenge even when sources are missing; a concrete problem outranks what is missing. |
| gsea-proteomics | partly | adopted the agent's method | method, own checks, grounding | Name the choice that decides the answer and judge it; scope each supported row to the check actually performed. |
| html-js-filter | yes | environment and portability | environment, own checks | A private, undocumented or version-specific symbol is a delivery risk; standard-library membership does not make it public. |
| interleaved-vigenere | yes | environment and portability | environment | A runtime data file the deliverable does not ship, and a fallback that continues after a failed load, are delivery risks. |
| music-harmony | no | hidden verifier quirk | grounding | Never imply agreement with a hidden grader; do not reassure beyond what you checked. |
| production-planning | yes | adopted the agent's premise | blockers, missing content, own checks | A blocker classification is the agent's claim, not evidence that authority is missing; a visible problem outranks what is missing. |
| roy-polymorph-cn | yes | adopted the agent's method | method, grounding, procedure | A result that holds only under the agent's assumption is not support; check what the agent asked to have checked. |

The n7 cases (`tests/fixtures/reviewer_accuracy/n7_cases.json`) had the decisive material in the
packet each time; the reviewer abstained on it or deferred to the agent's account:

| Case | Detectable | Miss | Lens or section | Directive (short form) |
| --- | --- | --- | --- | --- |
| observed-validator-outside-workspace | yes | abstained on observed output | grounding, own checks | Output FinishUP observed is a witness; never abstain or ask for a check's source only because it is outside the packet; a bare PASS line witnesses only that the check passed. |
| supplied-after-request | yes | re-listed supplied material | reading the packet | Supplied material includes the observed re-runs of a requested command; observed output, the change or a file answering the request is the witness, never withheld because the agent's answer was a summary. |
| disclosed-limit-with-decisive-fact | yes | deferred to a disclosure | review phase, blockers | `not_assessable` only when the packet holds no material that settles it; a disclosure is not support and never stops the reviewer judging the packet. |
| task-supplied-input-and-service | yes | delivery risk on correct work | environment | A run-time file the task supplies, and network access the task provides, are not delivery risks (issue #1094 R2-N1). |

The TB4 full-sol cases (`tests/fixtures/reviewer_accuracy/tb4_full_cases.json`) are bound to three
texts: the packet-only instruction, the loop instruction every review uses (which had dropped both
rules), and, for the withheld output, the closing review's acknowledged-obligation question:

| Case | Detectable | Miss | Lens or section | Directive (short form) |
| --- | --- | --- | --- | --- |
| conflicting-references-withheld-output | yes | endorsed a withheld output | blockers; loop Goal; acknowledged question | Name the strongest interpretation under which a required outcome is achievable; conflicting inputs are not inability, and agreeing a conflict exists is not permission to withhold. |
| unreachable-zero-budget | yes | unreachable recommendation | procedure; loop Clues | Suggest only inputs and states the visible interface can reach. |

The loop instruction keeps its byte budget (`test_instruction_is_one_short_pstack_prompt_with_the_honesty_rules`):
a new loop rule replaces a redundant sentence, so the minimal policy keeps its read room.

The spec and claim texts in the fixtures are synthetic paraphrases of each failure pattern, not task
text, and the investigations themselves are not part of the repository.

## Replay against a live reviewer (optional)

The offline check proves only that each directive is present. To measure whether a model follows
them, replay frozen packets through a provisioned test instance (ADR-028,
[test instances](test-instances.md)), never the live install:

1. Provision a test instance from the exact revision, with its own provider binding.
2. Build each case's packet from a copied, isolated state directory, or from a synthetic task that
   reproduces the pattern in the fixture.
3. Run one AI-powered review per case at the reviewer model and effort the benchmark uses, and
   record the conclusion, the challenges and the verified rows.
4. Count a case as caught only when a challenge or a `not_supported` row names the miss. A
   `not_assessable` row on the hidden-verifier case is the expected outcome, not a catch.
5. Compare against the N6 baseline: zero of the ten detectable misses were caught. For the n7
   cases, count an abstention (`insufficient_packet`, or a `not_assessable` row asking for a check's
   source) on the observed-validator case as a miss, and watch for the over-correction: a
   `supported` row that rests only on an observed bare PASS line. Keep the run count, the spread and
   the reviewer settings with the result.

Dispose of the test instance afterwards.

## Trade-off calibration and acceptance evidence (#1145, #1146)

Run the following alongside the offline checks above:

```text
uv run pytest tests/unit/adapters/providers/test_reviewer_judgment_calibration.py \
  tests/unit/application/test_review_judgment.py -q
```
The synthetic calibration cases cover nextjs-performance a2 (deferred loading versus initial
rendering), atrx-vep-crispr a1/a2 (task wording versus supplied reference), destructive reference
replacement, and a noisy single timing. They also cover the missed acceptance boundaries in biped,
ctr, freecad, pretrain, batched evaluation and payments. The expected response to ambiguity is
`decision_needed`, both interpretations with evidence, one cheap discriminating check, and a
choice recorded with `respond`; clear contradictory evidence against an unambiguous task still
supports a requirement finding. These checks make no provider call and cannot prove improved model
judgment. A live replay remains a separate, explicitly authorized evaluation.

Input-root behavior is shared by Codex, Claude Code and Cursor: the existing owner-admitted catalog
supplies current declared inputs and any retained snapshot. Verify declared-path boundaries and
root-removal fences with `tests/unit/application/test_reviewer_loop.py` and
`tests/unit/application/test_input_snapshot.py`. No root is admitted by reviewer instructions.


## Reviewer read recovery and attribution (#1173)

Run the scripted recovery checks without a provider or service install:

```text
uv run pytest tests/unit/application/test_reviewer_loop.py \
  tests/unit/domain/test_reviewer_reads.py \
  tests/integration/service/test_reviewer_read_recovery.py -q
```

The loop permits three content reads, at most five attempts and seven completions including
one format repair. Every attempt and response byte stays spent; retries share the original
deadline. A read returned after the reads end executes nothing and takes that one repair, which
asks for `final_judgment` only and is sent with the read-free reply schema; once the repair is
spent, every final turn is read-free. A review whose first turn offers no read (ask-every-time, or
a first turn inside the final reserve) keeps the read-free schema throughout. A schema-enforcing
route therefore always ends with a judgment; a read a route returns anyway ends `read_limit`. Refusal corrections are
fixed text per cause and never repeat the refused path; the instruction's file example uses the
placeholder `<relative-path>` and says a `path=.` listing that returns names spends a content
read. Paths are relative to issued aliases. Packet reads use exact catalog `item_id`;
ledger reads use `source_ref`/`linked_subject_refs` with the matching view in the frozen case.
An absent frozen item does not prove it was never recorded.

Owner-local metrics tooling that already holds an unlocked isolated test runtime can add:

```python
from finishup.application.reviewer_telemetry import export_reviewer_read_metrics

attempts = await runtime.ledger.list_semantic_attempts(job_id)
read_metrics = await export_reviewer_read_metrics(attempts, runtime.objects)
metrics["reviewer_read_usage"] = read_metrics
```

This reads the attempt's encrypted response, returning each call's validated selector/path
arguments and result code in `attempt_usages[].reviewer_reads`; it does not include returned
content, correction hints, judgments or packet text. It does not unlock storage or authorize an
export. Keep these selector-bearing metrics owner-local and apply the existing privacy rules
before sharing them. Structural diagnostics carry only action/result code, request id and
ordinal (`operation_count`); correlate them with the private metrics. Older responses or
missing/invalid objects yield null usage, so old failed calls cannot be reconstructed.

This shared path serves Codex, Claude Code and Cursor; CLI, MCP, TUI and receipts keep their
existing path-free record/projection and show both content reads and attempts when they differ.
No real-model accuracy or latency improvement is implied by the scripted checks.
