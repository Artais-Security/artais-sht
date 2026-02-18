from __future__ import annotations
import argparse, json
import httpx

from sht.checks import run_checks
from sht.grading import score_and_grade
from sht.remediation import remediation_text


def main() -> None:
    p = argparse.ArgumentParser(prog="sht", description="HTTP Security Headers Tester")
    p.add_argument("url")
    p.add_argument("--json", action="store_true", dest="as_json")
    p.add_argument("--follow-redirects", action="store_true", default=False)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--user-agent", default="sht/0.1.0")
    args = p.parse_args()

    headers = {"User-Agent": args.user_agent}
    with httpx.Client(follow_redirects=args.follow_redirects, timeout=args.timeout, headers=headers) as client:
        r = client.get(args.url)

    findings = run_checks(r)
    score, grade = score_and_grade(r, findings)

    if args.as_json:
        out = {
            "url": args.url,
            "final_url": str(r.url),
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "findings": [f.__dict__ for f in findings],
            "score": score,
            "grade": grade,
        }
        print(json.dumps(out, indent=2))
        return

    print(f"\n{grade} ({score}/100)  {r.status_code}  {r.url}\n")
    for f in findings:
        icon = {"pass":"✅", "warn":"⚠️", "fail":"❌", "info":"ℹ️"}.get(f.status, "•")
        print(f"{icon} {f.id}: {f.title} — {f.status.upper()}")
        if f.details:
            print(f"    {f.details}")
    print("\n---\nFix suggestions:\n")
    print(remediation_text(r, findings))
