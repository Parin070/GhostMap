from .base import Recon
from shodan import Shodan
from shodan.exception import APIError
import os
import requests
import aiohttp
import asyncio

class IPRecon(Recon):

    async def run(self):
        async with aiohttp.ClientSession() as session:
            abuse_task = self.fetch_abuseipdb(session)
            vt_task = self.fetch_virustotal(session)
            inf_task = self.fetch_ipinfo(session)
            abuse_response, vt_response, inf_response = await asyncio.gather(abuse_task, vt_task, inf_task)

        #Shodan
        try:
            api = Shodan(os.getenv("SHODAN"))
            shodan_response = api.host(self.target)
        except APIError:
            shodan_response = {}
        self.results = {
            "AbuseIPDB": abuse_response,
            "Shodan": shodan_response,
            "VirusTotal": vt_response,
            "IPInfo": inf_response
        }
        self.calculate_risk()

    async def fetch_ipinfo(self, session):
        url_inf = f"https://ipinfo.io/{self.target}/json"
        
        async with session.get(url_inf) as resp:
            return await resp.json()

        
    async def fetch_abuseipdb(self, session):
        #AbuseIPDB
        url_ab = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': self.target,
            'maxAgeInDays': '90'
        }

        headers_ab = {
            'Accept': 'application/json',
            'Key': os.getenv("ABUSEIPDB")
        }
        async with session.get(url_ab, headers=headers_ab, params=querystring) as resp:
            return await resp.json()
        
    async def fetch_virustotal(self, session):
        #VirusTotal
        url_vt = f"https://www.virustotal.com/api/v3/ip_addresses/{self.target}"
        headers_vt = {
            "accept": "application/json",
            "x-apikey": os.getenv("VIRUSTOTAL")
        }

        async with session.get(url_vt, headers=headers_vt) as resp:
            return await resp.json()

    def calculate_risk(self):
        abuse_score = self.results["AbuseIPDB"]["data"]["abuseConfidenceScore"]
        vt_stats = self.results["VirusTotal"]["data"]["attributes"]["last_analysis_stats"] 
        vt_score = (vt_stats["malicious"]/sum(vt_stats.values())) * 100
        shodan_score = 100 if self.results["Shodan"].get("vulns") else 0

        risk_score = (abuse_score + vt_score + shodan_score)/3
        self.results["risk_score"] = round(risk_score, 2)
        