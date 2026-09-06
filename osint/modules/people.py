from .base import Recon
from ddgs import DDGS
import subprocess
import re
import requests
import time

class PeopleRecon(Recon):
    def __init__(self, target, facts=None):
        super().__init__(target)
        self.facts = facts or []

    def run(self):
        if self.facts:
            self._run_deep_search(self.facts)
        elif " " in self.target:
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

    def _run_deep_search(self, facts):
        EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

        terms = " ".join([f'"{f}"' for f in facts])
        base_query = f'"{self.target}" {terms}'

        platforms = [
            "github.com", "linkedin.com", "facebook.com",
            "instagram.com", "twitter.com", "reddit.com",
            "tiktok.com", "pinterest.com", "youtube.com"
        ]

        queries = [base_query] + [f'{base_query} site:{p}' for p in platforms]
        found_urls = []
        for q in queries:
            try:
                with DDGS() as ddgs:
                    results = ddgs.text(q, max_results=10)
                    for r in results:
                        url = r.get("href", "")
                        if url:
                            found_urls.append(url)
            except Exception as e:
                print("DDGS ERROR: ", e)
            time.sleep(1)

        found_urls = list(set(found_urls))
        print("URLS FOUND:", len(found_urls), found_urls)

        emails_found = set()
        headers = {"User-Agent": "Mozilla/5.0"}
        for url in found_urls:
            try:
                resp = requests.get(url, headers=headers, timeout=8)
                if resp.status_code == 200:
                    emails_found.update(EMAIL_RE.findall(resp.text))
            except Exception:
                continue

        print("EMAILS FOUND:", emails_found)

        pivot_sources = {}
        for email in emails_found:
            pivot_urls = []
            try:
                with DDGS() as ddgs:
                    results = ddgs.text(f'"{email}"', max_results=15)
                    for r in results:
                        url = r.get("href", "")
                        if url:
                            pivot_urls.append(url)
            except Exception as e:
                pivot_urls.append(f"Error: {str(e)}")
            pivot_sources[email] = list(set(pivot_urls))
            time.sleep(1)

        self.results = {
            "DeepSearch": {
                "Full Name": self.target,
                "Facts": facts,
                "Query": base_query,
                "SourcesFound": found_urls,
                "EmailsFound": list(emails_found),
                "EmailPivotSources": pivot_sources
            }
        }