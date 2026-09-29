from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from dotenv import load_dotenv
import asyncio
from .modules.ip import IPRecon
from .modules.domain import DomainRecon
from .modules.email import EmailRecon
from .modules.people import PeopleRecon
from .modules.face import FaceRecon, pick_image, capture_camera, search_links
from .output.terminal import display_ip_results
from .output.terminal import display_domain_results
from .output.terminal import display_email_results
from .output.terminal import display_people_results
from .output.terminal import display_face_results
from .ai import summarize

console = Console()
ASCII_ART = """
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ███╗ █████╗ ██████╗ 
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
██║  ███╗███████║██║   ██║███████╗   ██║   ██╔████╔██║███████║██████╔╝
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝ 
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║██║  ██║██║     
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
"""

load_dotenv()

def main():
    console.print(Panel.fit(ASCII_ART, style = "bold cyan", title="[magenta]GhostMap v0.1[/magenta]", subtitle="[magenta]OSINT Recon Tool[/magenta]"))
    while True:
        console.print("\nWhat do you want to recon?", style="bold magenta")
        console.print("1. IP\n2. Domain\n3. Email\n4. People\n5. Facial Recon\n0. Exit\n", style="bold magenta")

        choice = (input("Enter your choice: "))
        if choice == "1":
            target = input("Enter IP: ")
            print(f"Running IP recon on {target}")
            recon = IPRecon(target)
            asyncio.run(recon.run())
            display_ip_results(recon.results)
            summary = summarize(recon.results, recon_type="IP")
            console.print(Markdown(summary["choices"][0]["message"]["content"]))
        elif choice == "2":
            target = input("Enter domain: ")
            print(f"Running domain recon on {target}")
            recon = DomainRecon(target)
            asyncio.run(recon.run())
            display_domain_results(recon.results)
            summary = summarize(recon.results, recon_type="Domain")
            console.print(Markdown(summary["choices"][0]["message"]["content"]))
        elif choice == "3":
            target = input("Enter email: ")
            print(f"Running email recon on {target}")
            recon = EmailRecon(target)
            recon.run()
            display_email_results(recon.results)
            summary = summarize(recon.results, recon_type="Email")
            console.print(Markdown(summary["choices"][0]["message"]["content"]))
        elif choice == "4":
            target = input("Enter username or full name: ")
            mode = input("Search as (1) username - Sherlock, (2) person name - dork: ")
            facts=[]
            if mode == "2":
                facts_input = input("Extra facts (comma-separated, optional): ").strip()
                if facts_input:
                    facts = [f.strip() for f in facts_input.split(",") if f.strip()]
                print(f"Running recon on {target}")
                recon = PeopleRecon(target, facts)
                recon.run()
            else:
                print(f"Running recon on {target}")
                recon = PeopleRecon(target)
                recon._run_sherlock()
            display_people_results(recon.results)
            summary = summarize(recon.results, recon_type="People")
            console.print(Markdown(summary["choices"][0]["message"]["content"]))
        elif choice == "5":
            src = input("Image source (1) file picker (2) camera (3) type path: ").strip()
            if src == "1":
                path = pick_image()
            elif src == "2":
                path = capture_camera()
            else:
                path = input("Image path: ").strip().strip('"')

            if not path:
                print("No image selected")
            else:
                pub = input("Public URL of image for reverse search (optional): ").strip()
                if pub:
                    for name, link in search_links(pub).items():
                        print(f"{name}: {link}")

                cand_input = input("Candidate URLs to verify (comma-separated, optional): ").strip()
                candidates = [c.strip() for c in cand_input.split(",") if c.strip()]

                print("Running face recon")
                recon = FaceRecon(path, candidates)
                recon.run()
                display_face_results(recon.results)
                if recon.results.get("matches"):
                    summary = summarize(recon.results, recon_type="Face")
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()