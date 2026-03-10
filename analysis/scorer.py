"""
Vulnerability Scorer
Scores entry points by exploitability and bounty potential
Higher score = test this first
"""


class VulnScorer:

    SEVERITY_SCORES = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 1,
    }

    TYPE_BONUSES = {
        "open_redirect": 3,
        "idor_candidate": 4,
        "file_upload": 4,
        "graphql_endpoint": 4,
        "api_endpoint": 3,
        "login_form": 3,
        "admin_panel": 4,
        "discovered_path": 2,
        "js_extracted_endpoint": 2,
        "interesting_subdomain": 2,
        "robots_disallowed": 1,
        "insecure_cookie": 1,
    }

    KEYWORD_BONUSES = {
        "admin": 2,
        "upload": 2,
        "file": 1,
        "payment": 3,
        "password": 2,
        "token": 2,
        "auth": 2,
        "api": 1,
        "user": 1,
        "account": 1,
        "secret": 3,
        "key": 2,
        "config": 2,
        ".env": 4,
        ".git": 4,
        "graphql": 3,
        "swagger": 2,
    }

    def score(self, entry_point):
        score = 0

        # Base severity score
        severity = entry_point.get("severity", "LOW")
        score += self.SEVERITY_SCORES.get(severity, 1)

        # Type bonus
        ep_type = entry_point.get("type", "")
        score += self.TYPE_BONUSES.get(ep_type, 0)

        # Keyword bonus from URL and detail
        text = (
            entry_point.get("url", "") +
            entry_point.get("param", "") +
            entry_point.get("detail", "")
        ).lower()

        for keyword, bonus in self.KEYWORD_BONUSES.items():
            if keyword in text:
                score += bonus

        # Phase bonus - full active findings are more confirmed
        phase = entry_point.get("phase", "")
        if phase == "full_active":
            score += 1
        elif phase == "light_active":
            score += 0.5

        # Status code bonuses
        status = entry_point.get("status_code")
        if status == 200:
            score += 2
        elif status == 403:
            score += 1  # Forbidden but exists - worth trying auth bypass

        return round(score, 1)
