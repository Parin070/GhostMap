from .base import Recon
import subprocess
from ddgs import DDGS

class PeopleRecon(Recon):
    def run(self):
        if " " in self.target:
            self._run_name_dork()
        else:
            self._run_sherlock()

    def _run_sherlock(self):
        result = subprocess.run(["sherlock", self.target], capture_output=True, text=True)
        found = []
        for line in result.stdout.split("\n"):
            if "[+]" in line:
                found.append(line.strip())

        self.results = {
            "Sherlock": {
                "Username": self.target,
                "Profiles": found
            }
        }

    def _run_name_dork(self):
        platforms = [
        "facebook.com", "linkedin.com", "instagram.com",
        "twitter.com", "reddit.com", "tiktok.com",
        "github.com", "pinterest.com", "youtube.com"
        ]

        site_query = " OR ".join([f"site:{p}" for p in platforms])
        query = f'"{self.target}" ({site_query})'

        found = []
        try:
            with DDGS() as ddgs:
                results = ddgs.text(query, max_results=15)
                for r in results:
                    url = r.get("href", "")
                    if url and any(p in url for p in platforms):
                        found.append(url)
        except Exception as e:
            found.append(f"Error: {str(e)}")

        self.results = {
            "NameDork": {
                "Full Name": self.target,
                "Query": query,
                "Profiles": list(set(found))
            }
        }