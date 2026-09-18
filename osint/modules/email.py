from .base import Recon
import requests
import re

class EmailRecon(Recon):
    def run(self):
        if self.validate_email():
            response = requests.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={self.target}")
            data = response.json()

            domain = self.target.split("@")[1]
            harvested = self._harvest_domain_emails(domain)
            pattern_result = self._detect_pattern(harvested, domain)

            self.results = {
                "Hudson Rock": data,
                "HarvestedEmails": harvested,
                "PatternGuess": pattern_result
            }
        else:
            self.results = {
                "error": "Invalid email format"
            }

        self.calculate_risk()

    def _harvest_domain_emails(self, domain):
        try:
            resp = requests.get(f"https://phonebook.cz/api/domain-osint/{domain}", timeout=10)
            print(f"[DEBUG] status: {resp.status_code}")
            print(f"[DEBUG] raw: {resp.text[:500]}")
            data = resp.json()
            emails = data.get("emails", [])
            return [e.get("email", "") if isinstance(e, dict) else e for e in emails]
        except Exception as e:
            print(f"[DEBUG] harvest error: {e}")
            return []


    def _detect_pattern(self, emails, domain):
        local_parts = [e.split("@")[0].lower() for e in emails if "@" in e and e.endswith("@" + domain)]

        patterns = {
            "first.last": r"^[a-z]+\.[a-z]+$",
            "firstlast": r"^[a-z]+[a-z]+$",
            "flast": r"^[a-z]\.?[a-z]{2,}$",
            "first_last": r"^[a-z]+_[a-z]+$",
            "first": r"^[a-z]+$",
            "lastfirst": r"^[a-z]+\.[a-z]$",
        }

        counts = {name: 0 for name in patterns}
        for local in local_parts:
            for name, rgx in patterns.items():
                if re.match(rgx, local):
                    counts[name] += 1
                    break  # first match wins, avoid double-count

        total = sum(counts.values())
        if total == 0:
            return {"pattern": "unknown", "confidence": 0, "sample_size": len(local_parts)}

        best = max(counts, key=counts.get)
        confidence = round((counts[best] / total) * 100, 1)

        return {"pattern": best, "confidence": confidence, "sample_size": len(local_parts), "matched_count": counts[best]}

    def calculate_risk(self):
        if "error" in self.results:
            self.results["risk_score"] = 0
            return
    
        breach_count = self.results["Hudson Rock"].get("total_user_services", 0)
    
        if breach_count == 0:
            risk_score = 0
        elif breach_count < 10:
            risk_score = 30
        elif breach_count < 50:
            risk_score = 60
        else:
            risk_score = 100
    
        self.results["risk_score"] = risk_score

    def validate_email(self):
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, self.target))