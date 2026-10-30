"""Fixed FinishUP guidance, separate from privacy-projected reviewer prose."""

from enum import StrEnum


class ReviewGuidance(StrEnum):
    MATERIAL_CONCERNS = (
        "Non-blocking. For each material concern: run a proportionate check, cite evidence that "
        "already settles it, or decline with a reason. Answer each material one once; zero "
        "findings does not establish correctness. A failing or weak test result: fix it; if you "
        "cannot, disclose it by name."
    )


def review_guidance_line(value: object) -> str:
    if value is ReviewGuidance.MATERIAL_CONCERNS or (
        type(value) is str and value == ReviewGuidance.MATERIAL_CONCERNS.value
    ):
        return "FinishUP guidance: " + ReviewGuidance.MATERIAL_CONCERNS.value
    return ""
