from rich.console import Console
from rich.table import Table

console = Console()

def display_ip_results(results):
    print("IP Report\n")

    #AbuseIPDB
    table_ab = Table(title="AbuseIPDB")
    table_ab.add_column("Field", justify="center", style="cyan")
    table_ab.add_column("Value", justify="center", style="magenta")

    table_ab.add_row("Abuse Score", str(results["AbuseIPDB"]["data"]["abuseConfidenceScore"]))
    table_ab.add_row("Total Reports", str(results["AbuseIPDB"]["data"]["totalReports"]))
    table_ab.add_row("Distinct Users", str(results["AbuseIPDB"]["data"]["numDistinctUsers"]))
    table_ab.add_row("Tor Exit Node", str(results["AbuseIPDB"]["data"]["isTor"]))
    table_ab.add_row("Last Reported", str(results["AbuseIPDB"]["data"]["lastReportedAt"]))

    console.print(table_ab)

    print()

    #Shodan
    table_sh = Table(title="Shodan")
    table_sh.add_column("Field", justify="center", style="cyan")
    table_sh.add_column("Value", justify="center", style="magenta")

    table_sh.add_row("Organization", str(results["Shodan"].get("org", "N/A")))
    table_sh.add_row("ISP", str(results["Shodan"].get("isp", "N/A")))
    location = f"{results['Shodan'].get('city', 'N/A')}, {results['Shodan'].get('country_name', 'N/A')}"
    table_sh.add_row("Location", location)
    table_sh.add_row("ASN", str(results["Shodan"].get("asn", "N/A")))
    table_sh.add_row("Ports", str(results["Shodan"].get("ports", "N/A")))
    table_sh.add_row("Hostnames", str(results["Shodan"].get("hostnames", "N/A")))
    table_sh.add_row("CVEs", str(results["Shodan"].get("vulns", "None Found")))

    console.print(table_sh)

    print()

    #ipinfo
    table_inf = Table(title="IPInfo")
    table_inf.add_column("Field", justify="center", style="cyan")
    table_inf.add_column("Value", justify="center", style="magenta")

    inf = results["IPInfo"]
    table_inf.add_row("Hostname", str(inf.get("hostname", "N/A")))
    table_inf.add_row("City", str(inf.get("city", "N/A")))
    table_inf.add_row("Reigon", str(inf.get("reigon", "N/A")))
    table_inf.add_row("Country", str(inf.get("country", "N/A")))
    table_inf.add_row("Coordinates", str(inf.get("loc", "N/A")))
    table_inf.add_row("Postal", str(inf.get("postal", "N/A")))
    table_inf.add_row("Timezone", str(inf.get("timezone", "N/A")))

    console.print(table_inf)

    print()

    #VirusTotal - Add range for values
    table_vt = Table(title="VirusTotal")
    table_vt.add_column("Field", justify="center", style="cyan")
    table_vt.add_column("Value", justify="center", style="magenta")

    vt = results["VirusTotal"]["data"]["attributes"]
    table_vt.add_row("Malicious", str(vt["last_analysis_stats"]["malicious"]))
    table_vt.add_row("Harmless", str(vt["last_analysis_stats"]["harmless"]))
    table_vt.add_row("Suspicious", str(vt["last_analysis_stats"]["suspicious"]))
    table_vt.add_row("Reputation", str(vt["reputation"]))
    table_vt.add_row("AS Owner", vt["as_owner"])

    console.print(table_vt)

    print()

    # Risk Score
    table_rs = Table(title="Risk Score")
    table_rs.add_column("Field", justify="center", style="cyan")
    table_rs.add_column("Value", justify="center", style="magenta")

    table_rs.add_row("Risk Score", str(results["risk_score"]))

    console.print(table_rs)

def display_domain_results(results):
    print("Domain Report")

    #Whois
    table_wh = Table(title="Whois")
    table_wh.add_column("Field", justify="center", style="cyan")
    table_wh.add_column("Value", justify="center", style="magenta")

    table_wh.add_row("Registrar", str(results["Whois"]["Registrar"]))
    table_wh.add_row("Creation Date", str(results["Whois"]["Creation Date"]))
    table_wh.add_row("Expiration Date", str(results["Whois"]["Expiration Date"]))
    table_wh.add_row("Name Servers", str(results["Whois"]["Name Servers"]))
    table_wh.add_row("Organisation", str(results["Whois"]["Org"]))

    #Tech Stack
    print()
    table_ts = Table(title="Tech Stack")
    table_ts.add_column("Field", justify="center", style="cyan")
    table_ts.add_column("Value", justify="center", style="magenta")

    ts = results.get("TechStack", {})
    if "error" in ts:
        table_ts.add_row("Status", f"[red]{ts['error']}[/red]")
    else:
        table_ts.add_row("Detected", "\n".join(ts.get("Detected", [])) or "None")
        table_ts.add_row("Server", str(ts.get("Server", "Unknown")))
        table_ts.add_row("Powered By", str(ts.get("PoweredBy", "Unknown")))

    console.print(table_ts)

    console.print(table_wh)
    if "Company" in results:
        print()
        table_co = Table(title="Company Intel")
        table_co.add_column("Field", justify="center", style="cyan")
        table_co.add_column("Value", justify="center", style="magenta")

        co = results["Company"]
        if "error" in co:
            table_co.add_row("Status", f"[red]{co['error']}[/red]")
        else:
            table_co.add_row("Name", str(co["Name"]))
            table_co.add_row("Status", str(co["Status"]))
            table_co.add_row("Jurisdiction", str(co["Jurisdiction"]))
            table_co.add_row("Category", str(co["Category"]))
            table_co.add_row("Country", str(co["Country"]))
            table_co.add_row("HQ City", str(co["HQ City"]))
            table_co.add_row("LEI Status", str(co["LEI Status"]))
            table_co.add_row("Last Updated", str(co["Last Updated"]))
            table_co.add_row("Next Renewal", str(co["Next Renewal"]))
            table_co.add_row("Corroboration", str(co["Corroboration"]))

        console.print(table_co)

    if "FinancialDork" in results:
        print()
        table_fd = Table(title="Financial Intelligence")
        table_fd.add_column("Title", style="cyan")
        table_fd.add_column("Snippet", style="magenta")
        table_fd.add_column("URL", style="green")

        fd = results["FinancialDork"]
        if "error" in fd:
            table_fd.add_row("Error", fd["error"], "")
        else:
            for r in fd["Results"]:
                if "error" in r:
                    table_fd.add_row("Error", r["error"], "")
                else:
                    table_fd.add_row(
                        str(r["title"]),
                        str(r["snippet"]),
                        str(r["url"])
                    )

        console.print(table_fd)

    print()


    #DNS
    table_dns = Table(title="DNS")
    table_dns.add_column("Field", justify="center", style="cyan")
    table_dns.add_column("Value", justify="center", style="magenta")

    table_dns.add_row("A", "\n".join(results["DNS"]["A"]))
    table_dns.add_row("MX", "\n".join(results["DNS"]["MX"]))
    table_dns.add_row("TXT", "\n".join(results["DNS"]["TXT"]))

    console.print(table_dns)

    print()

    #crt.sh
    table_crt = Table(title="Subdomains")
    table_crt.add_column("Field", justify="center", style="cyan")

    for sub in results["Subdomains"]:
        table_crt.add_row(sub)

    console.print(table_crt)

    print()
    
    #VirusTotal
    table_vt = Table(title="VirusTotal")
    table_vt.add_column("Field", justify="center", style="cyan")
    table_vt.add_column("Value", justify="center", style="magenta")

    vt = results["VirusTotal"]["data"]["attributes"]
    table_vt.add_row("Malicious", str(vt["last_analysis_stats"]["malicious"]))
    table_vt.add_row("Harmless", str(vt["last_analysis_stats"]["harmless"]))
    table_vt.add_row("Suspicious", str(vt["last_analysis_stats"]["suspicious"]))
    table_vt.add_row("Reputation", str(vt["reputation"]))

    console.print(table_vt)

    print()    

    # Risk Score
    table_rs = Table(title="Risk Score")
    table_rs.add_column("Field", justify="center", style="cyan")
    table_rs.add_column("Value", justify="center", style="magenta")

    table_rs.add_row("Risk Score", str(results["risk_score"]))

    console.print(table_rs)

def display_email_results(results):
    print("Email Report")
    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return
    
    #Hudson Rock
    table_hr = Table(title="Huson Rock")
    table_hr.add_column("Field", justify="center", style="cyan")
    table_hr.add_column("Value", justify="center", style="magenta")

    hr = results["Hudson Rock"]
    table_hr.add_row("Total User Services", str(hr.get("total_user_services", 0)))
    table_hr.add_row("Total Corporate Services", str(hr.get("total_corporate_services", 0)))
    table_hr.add_row("Infections Found", str(len(hr.get("stealers", []))))
    
    if hr.get("stealers"):
        latest = hr["stealers"][0]
        table_hr.add_row("Most Recent Infection", latest.get("date_compromised", "N/A"))
        table_hr.add_row("Computer Name", latest.get("computer_name", "N/A"))
        table_hr.add_row("OS", latest.get("operating_system", "N/A"))
    
    console.print(table_hr)
    
    print()

    # Harvested Emails
    table_he = Table(title="Harvested Emails")
    table_he.add_column("Field", justify="center", style="cyan")
    table_he.add_column("Value", justify="center", style="magenta")

    harvested = results.get("HarvestedEmails", [])
    table_he.add_row("Total Found", str(len(harvested)))
    if harvested:
        sample = ", ".join(harvested[:5])
        table_he.add_row("Sample", sample)

    console.print(table_he)

    print()

    # Pattern Guess
    table_pg = Table(title="Email Pattern")
    table_pg.add_column("Field", justify="center", style="cyan")
    table_pg.add_column("Value", justify="center", style="magenta")

    pg = results.get("PatternGuess", {})
    table_pg.add_row("Detected Pattern", pg.get("pattern", "unknown"))
    table_pg.add_row("Confidence", f"{pg.get('confidence', 0)}%")
    table_pg.add_row("Sample Size", str(pg.get("sample_size", 0)))

    console.print(table_pg)

    print()

    # Risk Score
    table_rs = Table(title="Risk Score")
    table_rs.add_column("Field", justify="center", style="cyan")
    table_rs.add_column("Value", justify="center", style="magenta")

    table_rs.add_row("Risk Score", str(results["risk_score"]))

    console.print(table_rs)
    print()

def display_people_results(results):
    table = Table(title="Profiles")
    table.add_column("Profile URL", style="cyan")

    if "Sherlock" in results:
        data = results["Sherlock"]
        table.title = f"Sherlock — {data['Username']}"
        for profile in data["Profiles"]:
            table.add_row(profile)

    elif "NameDork" in results:
        data = results["NameDork"]
        table.title = f"Name Search — {data['Full Name']}"
        for profile in data["Profiles"]:
            table.add_row(profile)

    elif "DeepSearch" in results:
        data = results["DeepSearch"]
        table.title = f"Deep Search — {data['Full Name']}"
        table.add_row(f"[bold]Facts:[/bold] {', '.join(data['Facts'])}")
        table.add_row("[bold]— Sources Found —[/bold]")
        for url in data["SourcesFound"]:
            table.add_row(url)
        table.add_row("[bold]— Emails Found —[/bold]")
        for email in data["EmailsFound"]:
            table.add_row(email)
        table.add_row("[bold]— Email Pivot Sources —[/bold]")
        for email, urls in data["EmailPivotSources"].items():
            table.add_row(f"[yellow]{email}[/yellow]")
            for url in urls:
                table.add_row(f"  {url}")

    console.print(table)