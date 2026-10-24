"""Fixed FinishUP guidance, separate from privacy-projected reviewer prose."""

from enum import StrEnum


class ReviewGuidance(StrEnum):
    MATERIAL_CONCERNS = (
        "Assess material review concerns against the task and evidence. Run a proportionate "
        "check, cite settling evidence, explain disagreement, or disclose remaining uncertainty. "
        "Recording a response is optional; zero findings does not establish correctness."
    )


def review_guidance_line(value: object) -> str:
    if value is ReviewGuidance.MATERIAL_CONCERNS or (
        type(value) is str and value == ReviewGuidance.MATERIAL_CONCERNS.value
    ):
        return "FinishUP guidance: " + ReviewGuidance.MATERIAL_CONCERNS.value
    return ""
