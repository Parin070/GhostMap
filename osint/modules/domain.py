from .base import Recon
from ddgs import DDGS
from bs4 import BeautifulSoup
import whois
import tldextract
import dns.asyncresolver
import aiohttp
import asyncio
import os
import re


TECH_FINGERPRINTS = {
    "WordPress":     {"meta": [r'generator["\']?\s*content=["\']WordPress'], "path": [r'/wp-content/', r'/wp-includes/']},
    "Shopify":       {"cookie": [r'_shopify_'], "script": [r'cdn\.shopify\.com']},
    "Wix":           {"meta": [r'generator["\']?\s*content=["\']Wix'], "script": [r'static\.wixstatic\.com']},
    "Squarespace":   {"script": [r'static1\.squarespace\.com']},
    "Webflow":       {"meta": [r'generator["\']?\s*content=["\']Webflow']},
    "Drupal":        {"meta": [r'generator["\']?\s*content=["\']Drupal'], "header": [r'X-Generator:\s*Drupal'], "cookie": [r'SESS[a-f0-9]{32}']},
    "Joomla":        {"meta": [r'generator["\']?\s*content=["\']Joomla']},
    "Magento":       {"cookie": [r'frontend'], "script": [r'/mage/', r'Mage\.Cookies']},
    "Next.js":       {"script": [r'/_next/static/'], "header": [r'X-Powered-By:\s*Next\.js']},
    "Nuxt.js":       {"script": [r'/_nuxt/']},
    "React":         {"script": [r'react(\.min)?\.js', r'react-dom']},
    "Vue.js":        {"script": [r'vue(\.min)?\.js']},
    "Angular":       {"script": [r'angular(\.min)?\.js'], "path": [r'ng-version']},
    "jQuery":        {"script": [r'jquery(-\d+\.\d+\.\d+)?(\.min)?\.js']},
    "Bootstrap":     {"script": [r'bootstrap(\.min)?\.js'], "path": [r'bootstrap(\.min)?\.css']},
    "Tailwind CSS":  {"path": [r'tailwind(\.min)?\.css']},
    "Cloudflare":    {"header": [r'Server:\s*cloudflare', r'CF-Ray:']},
    "Nginx":         {"header": [r'Server:\s*nginx']},
    "Apache":        {"header": [r'Server:\s*Apache']},
    "Vercel":        {"header": [r'X-Vercel-Id:', r'Server:\s*Vercel']},
    "Netlify":       {"header": [r'X-NF-Request-Id:', r'Server:\s*Netlify']},
    "PHP":           {"header": [r'X-Powered-By:\s*PHP']},
    "ASP.NET":       {"header": [r'X-Powered-By:\s*ASP\.NET', r'X-AspNet-Version:']},
    "Laravel":       {"cookie": [r'laravel_session', r'XSRF-TOKEN']},
    "Django":        {"cookie": [r'csrftoken', r'sessionid']},
    "Express":       {"header": [r'X-Powered-By:\s*Express']},
    "Google Analytics": {"script": [r'google-analytics\.com/analytics\.js', r'googletagmanager\.com/gtag']},
    "Hotjar":        {"script": [r'static\.hotjar\.com']},
    "Stripe":        {"script": [r'js\.stripe\.com']},
    "reCAPTCHA":     {"script": [r'google\.com/recaptcha']},
    "HubSpot":       {"script": [r'js\.hs-scripts\.com', r'js\.hsforms\.net']},
    "Intercom":      {"script": [r'widget\.intercom\.io']},
    "Flask":         {"cookie": [r'session=\.eJ'], "header": [r'Server:\s*Werkzeug']},
    "FastAPI":       {"header": [r'Server:\s*uvicorn'], "path": [r'/docs.*swagger', r'/openapi\.json']},
    "Ruby on Rails": {"cookie": [r'_session_id'], "header": [r'X-Powered-By:\s*Phusion', r'Server:\s*Passenger']},
    "Spring Boot":   {"header": [r'X-Application-Context:'], "path": [r'/actuator/']},
    "Go (net/http)": {"header": [r'Server:\s*$']},  # weak signal, Go often omits Server header
    "Node.js":       {"header": [r'X-Powered-By:\s*Express', r'Server:\s*Node']},
    "Gunicorn":      {"header": [r'Server:\s*gunicorn']},
    "uWSGI":         {"header": [r'Server:\s*uWSGI']}
}

UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}


def _match_signals(fp, headers_blob, html_blob, cookie_blob):
    blob_map = {
        "header": headers_blob, "meta": html_blob, "script": html_blob,
        "path": html_blob, "html": html_blob, "cookie": cookie_blob,
    }
    for sig_type, patterns in fp.items():
        blob = blob_map.get(sig_type, "")
        for pat in patterns:
            if re.search(pat, blob, re.IGNORECASE):
                return True
    return False

def headers_blob_get(headers_blob, key):
    for line in headers_blob.splitlines():
        if line.lower().startswith(key.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return "Unknown"

class DomainRecon(Recon):

    async def run(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12))
        loop = asyncio.get_event_loop()

        try:
            # Phase 1 — independent lookups, all parallel
            whois_task   = loop.run_in_executor(None, self._whois_lookup)
            dns_task     = self._dns_lookup()
            crtsh_task   = self._crtsh_lookup()
            vt_task      = self._vt_lookup()
            tech_task    = self._techstack_lookup()
            meta_task    = self._scrape_page_meta()

            who, dns_res, subdomains, vt_response, techstack, page_meta = await asyncio.gather(
                whois_task, dns_task, crtsh_task, vt_task, tech_task, meta_task
            )

            self.results = {
                "Whois": {
                    "Registrar": who.registrar,
                    "Org": who.org,
                    "Creation Date": who.creation_date,
                    "Expiration Date": who.expiration_date,
                    "Name Servers": who.name_servers
                },
                "DNS": dns_res,
                "Subdomains": subdomains,
                "VirusTotal": vt_response,
                "TechStack": techstack,
                "PageMeta": page_meta
            }

            self.calculate_risk()

            # Phase 2 — depends on Whois org, run parallel
            org = self._resolve_org()
            company_task = loop.run_in_executor(None, self._run_company_check, org)
            dork_task = loop.run_in_executor(None, self._run_financial_dork, org)

            company_result, dork_result = await asyncio.gather(company_task, dork_task)
            self.results["Company"] = company_result
            self.results["FinancialDork"] = dork_result

            # Phase 3 — depends on dork links
            self.results["FinancialContent"] = await self._fetch_financial_content()

        finally:
            await self.session.close()

    # ---------------- Phase 1 tasks ----------------

    def _whois_lookup(self):
        try:
            return whois.whois(self.target)
        except Exception as e:
            class _Empty: pass
            w = _Empty()
            w.registrar = None
            w.org = None
            w.creation_date = None
            w.expiration_date = None
            w.name_servers = None
            w.error = str(e)
            return w

    async def _dns_lookup(self):
        resolver = dns.asyncresolver.Resolver()

        async def _resolve(rtype):
            try:
                answers = await resolver.resolve(self.target, rtype)
                return [r.to_text() for r in answers]
            except Exception:
                return []

        a_list, mx_list, txt_list = await asyncio.gather(
            _resolve("A"), _resolve("MX"), _resolve("TXT")
        )
        return {"A": a_list, "MX": mx_list, "TXT": txt_list}

    async def _crtsh_lookup(self):
        try:
            async with self.session.get(f"https://crt.sh/?q={self.target}&output=json") as resp:
                data = await resp.json(content_type=None)
                subdomains = set(entry["name_value"] for entry in data)
                return list(subdomains)[:20]
        except Exception:
            return []

    async def _vt_lookup(self):
        url_vt = f"https://www.virustotal.com/api/v3/domains/{self.target}"
        headers_vt = {"accept": "application/json", "x-apikey": os.getenv("VIRUSTOTAL")}
        try:
            async with self.session.get(url_vt, headers=headers_vt) as resp:
                return await resp.json()
        except Exception as e:
            return {"error": str(e)}

    async def _scrape_page_meta(self):
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"Title": "", "Description": "", "OG_Description": "", "H1": ""}
        headers = {
            "User-Agent": UA["User-Agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        try:
            async with self.session.get(url, headers=headers, ssl=False, allow_redirects=True) as resp:
                html = await resp.text(errors="ignore")
                if len(html) < 500 or resp.status >= 400:
                    html, _, _ = await self._fetch_wayback(url)
        except Exception:
            html, _, _ = await self._fetch_wayback(url)

        if not html:
            return result

        soup = BeautifulSoup(html, "html.parser")
        if soup.title:
            result["Title"] = soup.title.get_text(strip=True)

        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            result["Description"] = meta_desc["content"].strip()

        og_desc = soup.find("meta", attrs={"property": "og:description"})
        if og_desc and og_desc.get("content"):
            result["OG_Description"] = og_desc["content"].strip()

        h1 = soup.find("h1")
        if h1:
            result["H1"] = h1.get_text(strip=True)

        return result

    async def _techstack_lookup(self):
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"Detected": [], "Server": "Unknown", "PoweredBy": "Unknown", "Source": "live"}

        headers = {
            "User-Agent": UA["User-Agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }

        html, headers_blob, cookie_blob, status = await self._fetch_live(url, headers)

        if status is None or status >= 400 or len(html) < 500:
            # live fetch blocked or empty — fall back to wayback snapshot
            html, headers_blob, cookie_blob = await self._fetch_wayback(url)
            result["Source"] = "wayback" if html else "blocked"

        if html:
            for tech, fp in TECH_FINGERPRINTS.items():
                if _match_signals(fp, headers_blob, html, cookie_blob):
                    result["Detected"].append(tech)

            gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.IGNORECASE)
            if gen_match:
                result["Generator"] = gen_match.group(1)

        if result["Source"] == "live":
            result["Server"] = headers_blob_get(headers_blob, "Server")
            result["PoweredBy"] = headers_blob_get(headers_blob, "X-Powered-By")

        return result


    async def _fetch_live(self, url, headers):
        try:
            async with self.session.get(url, headers=headers, ssl=False, allow_redirects=True) as resp:
                html = await resp.text(errors="ignore")
                headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                cookie_blob = "\n".join(f"{c.key}={c.value}" for c in resp.cookies.values())
                return html, headers_blob, cookie_blob, resp.status
        except Exception:
            return "", "", "", None


    async def _fetch_wayback(self, url):
        try:
            api = f"http://archive.org/wayback/available?url={url}"
            async with self.session.get(api, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                data = await resp.json()
                snap = data.get("archived_snapshots", {}).get("closest", {}).get("url")
            if not snap:
                return "", "", ""
            async with self.session.get(snap, headers=UA, timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                html = await resp2.text(errors="ignore")
                return html, "", ""
        except Exception:
            return "", "", ""

    # ---------------- risk + org resolution ----------------

    def calculate_risk(self):
        try:
            vt_stats = self.results["VirusTotal"]["data"]["attributes"]["last_analysis_stats"]
            vt_score = (vt_stats["malicious"] / sum(vt_stats.values())) * 100
            self.results["risk_score"] = round(vt_score, 2)
        except Exception:
            self.results["risk_score"] = None

    def _resolve_org(self):
        org = self.results["Whois"].get("Org")
        if not org or len(org) < 3:
            org = self._extract_name_from_domain()

        domain_name = tldextract.extract(self.target).domain.lower()
        if domain_name not in org.lower():
            org = self._extract_name_from_domain()

        proxy_keywords = ["privacy", "proxy", "protect", "whoisguard", "domains by proxy", "redacted"]
        if any(kw in org.lower() for kw in proxy_keywords):
            org = self._extract_name_from_domain()

        return org

    # ---------------- Phase 2 tasks (sync, run in executor) ----------------

    def _run_company_check(self, org):
        import requests
        cleaned_org = self._clean_org(org)
        try:
            response = requests.get(
                "https://api.gleif.org/api/v1/lei-records",
                params={"filter[entity.legalName]": cleaned_org, "page[size]": 1},
                headers={"Accept": "application/vnd.api+json"},
                timeout=10
            )
            data = response.json()
            records = data.get("data", [])

            if not records:
                return {"error": "No records found", "org": org}

            top = records[0]["attributes"]["entity"]
            reg = records[0]["attributes"]["registration"]

            return {
                "Name": top["legalName"]["name"],
                "Status": top["status"],
                "Jurisdiction": top.get("jurisdiction", "N/A"),
                "Category": top.get("category", "N/A"),
                "Country": top["legalAddress"]["country"],
                "HQ City": top["headquartersAddress"].get("city", "N/A"),
                "LEI Status": reg["status"],
                "Last Updated": reg["lastUpdateDate"],
                "Next Renewal": reg["nextRenewalDate"],
                "Corroboration": reg["corroborationLevel"]
            }
        except Exception as e:
            return {"error": str(e)}

    def _clean_org(self, org):
        suffixes = r'\b(LLC|Inc\.?|Ltd\.?|Corp\.?|Co\.?|Limited|Incorporated|Corporation|GmbH|PLC|AG)\b'
        return re.sub(suffixes, '', org, flags=re.IGNORECASE).strip().strip(',').strip()

    def _run_financial_dork(self, org):
        query = f'"{org}" OR "{self.target}" revenue OR "annual report" OR "financial results" OR earnings'
        links = []
        try:
            with DDGS() as ddgs:
                results = ddgs.text(query, max_results=5)
                for r in results:
                    links.append({
                        "title": r.get("title", ""),
                        "url": r.get("href", ""),
                        "snippet": r.get("body", "")[:150]
                    })
        except Exception as e:
            links.append({"error": str(e)})

        return {"Org": org, "Results": links}

    # ---------------- Phase 3 — financial content, async, parallel fetch ----------------

    async def _fetch_financial_content(self):
        fd = self.results.get("FinancialDork", {})
        results = fd.get("Results", [])
        urls = [r["url"] for r in results if "url" in r][:3]

        async def _fetch_one(url):
            try:
                async with self.session.get(url, headers=UA, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    html = await resp.text(errors="ignore")
                    soup = BeautifulSoup(html, "html.parser")
                    for tag in soup(["script", "style", "nav", "footer"]):
                        tag.decompose()
                    text = soup.get_text(separator=" ", strip=True)[:2000]
                    return f"\n\nSOURCE: {url}\n{text}"
            except Exception:
                return ""

        if not urls:
            return ""

        chunks = await asyncio.gather(*[_fetch_one(u) for u in urls])
        return "".join(chunks)

    def _extract_name_from_domain(self):
        extracted = tldextract.extract(self.target)
        return extracted.domain.capitalize()