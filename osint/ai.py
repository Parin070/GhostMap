import requests
import os

def summarize(results, recon_type="target"):
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.getenv('OPENROUTER')}",
            "Content-Type": "application/json"
        },
        json={
            "model": "openrouter/free",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity analyst and OSINT researcher. "
                        "Analyze this OSINT scan data. Give TWO sections:\n"
                        "1. Overview — what/who this target is, based on available data "
                        "(org name, tech stack, page title/description for domains; "
                        "ISP/org/geo for IPs; breach/registration data for emails; "
                        "aggregated profile hits for people). Be concrete, not generic.\n"
                        "2. Risk Assessment — flag anything suspicious, give risk verdict."
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"Recon type: {recon_type}. "
                        f"Here is OSINT scan data: {results}. "
                        f"Give Overview then Risk Assessment."
                    )
                }
            ]
        }
    )
    return response.json()