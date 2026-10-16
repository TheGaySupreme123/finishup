# Reviewer instruction evaluation runbook

Use this runbook when you change `SEMANTIC_REVIEW_INSTRUCTION`, a lens, the grounding rules or the
review-phase questions. It checks the instruction against the reviewer misses the N6 D-lane audit
investigated (issue #1082). The design and the reasons are in
[ADR-006](../adr/ADR-006-semantic-provider-profile.md), "The reviewer instruction as a procedure
with named lenses".

## Run the offline check

The offline check makes no provider call and needs no service:

```text
uv run pytest tests/unit/adapters/providers/test_reviewer_accuracy_directives.py \
  tests/unit/adapters/providers/test_reviewer_instruction.py \
  tests/unit/adapters/providers/test_task_statement_instruction.py -q
```

It fails when:

- a case no longer names a lens or section that targets its miss;
- a directive sentence a case relies on moved out of its lens or section, or was reworded;
- a lens lost its failure example, or the procedure no longer precedes the reference material;
- the instruction names an evaluation case or its domain words, which would fit the instruction to
  the evaluation set.

A failure here is a decision, not a chore. When you reword a directive on purpose, update the
case in `tests/fixtures/reviewer_accuracy/n6_cases.json` and say in the pull request why the new
wording still targets that miss.

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

The spec and claim texts in the fixture are synthetic paraphrases of each failure pattern, not task
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
5. Compare against the N6 baseline: zero of the ten detectable misses were caught. Keep the run
   count, the spread and the reviewer settings with the result.

Dispose of the test instance afterwards.
