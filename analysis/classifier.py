"""
Entry Point Classifier
Maps discovered entry points to attack categories
"""


class EntryPointClassifier:
    
    ATTACK_MAPS = {
        "idor_candidate": ["IDOR", "Broken Object Level Auth"],
        "api_endpoint": ["IDOR", "Auth Bypass", "Rate Limiting", "Mass Assignment"],
        "api_endpoint_auth": ["Auth Bypass", "JWT Attacks", "Token Theft"],
        "login_form": ["SQLi", "Credential Stuffing", "Account Enumeration", "Brute Force"],
        "search_form": ["XSS", "SQLi", "SSTI"],
        "file_upload": ["Unrestricted File Upload", "Path Traversal", "RCE"],
        "post_form": ["CSRF", "XSS", "SQLi", "Mass Assignment"],
        "open_redirect": ["Open Redirect", "OAuth Token Theft", "Phishing"],
        "graphql_endpoint": ["GraphQL Introspection", "IDOR", "Batching Attack", "NoSQL Injection"],
        "interesting_subdomain": ["Subdomain Takeover", "Different Auth Surface"],
        "robots_disallowed": ["Hidden Functionality", "Auth Bypass"],
        "discovered_path": ["Auth Bypass", "Info Disclosure"],
        "js_extracted_endpoint": ["IDOR", "Auth Bypass", "Injection"],
        "insecure_cookie": ["Session Hijacking via XSS"],
        "admin_panel": ["Auth Bypass", "Privilege Escalation"],
        "param_url": ["IDOR", "SQLi", "XSS", "Path Traversal"],
        "wayback_param": ["IDOR", "SQLi", "XSS"],
        "dns_info_disclosure": ["Credential Exposure"],
        "general_form": ["XSS", "SQLi", "CSRF"],
    }

    def classify(self, entry_point):
        ep_type = entry_point.get("type", "")
        return self.ATTACK_MAPS.get(ep_type, ["Manual Investigation"])
