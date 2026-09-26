import os
import logging
from google import genai
from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)

MODEL = "gemini-2.0-flash"


def generate_plain_english_summary(domain: str, all_findings: list[SecurityFinding]) -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "AI summary unavailable — API key not configured."

    if not all_findings:
        return f"No findings were available to summarize for {domain}."

    findings_text = "\n".join(
        f"- [{f.severity.upper()}] {f.message}" for f in all_findings
    )

    prompt = f"""You are explaining a cybersecurity scan's results to someone with no technical background.

Domain scanned: {domain}

Findings:
{findings_text}

Write a short (3-5 sentence) plain-English summary of what these findings mean overall, and whether the domain looks generally safe, risky, or somewhere in between. Avoid jargon. Do not repeat the raw findings verbatim — explain what they mean in practice."""

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=MODEL,
            contents=prompt
        )
        return response.text
    except Exception as e:
        logger.error(f"AI summary generation failed: {e}")
        return "AI summary could not be generated at this time."