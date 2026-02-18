from __future__ import annotations

def score_and_grade(resp, findings):
    score = 100
    for f in findings:
        if f.status == "fail":
            score -= 25 if f.severity == "high" else 15
        elif f.status == "warn":
            score -= 10 if f.severity in ("med", "high") else 5
    score = max(0, min(100, score))

    if score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    else: grade = "F"
    return score, grade
