"""
DMARC, SPF & DKIM Record Checker
License: GNU General Public License v3.0
Author: learnwithaq.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import dns.resolver
from termcolor import colored

def check_dmarc(domain):
    """Check DMARC record for the domain and highlight policy."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in answers:
            record_text = record.to_text().strip('"')
            if "v=DMARC1" in record_text:
                # Extract and color policy
                policy = "unknown"
                if "p=none" in record_text:
                    policy = colored("p=none", "red")
                elif "p=quarantine" in record_text:
                    policy = colored("p=quarantine", "yellow")
                elif "p=reject" in record_text:
                    policy = colored("p=reject", "cyan")
                else:
                    policy = colored("p=unknown", "magenta")

                print(colored(f"[✓] DMARC record found: ", "green") + record_text)
                print(colored("[*] DMARC Policy: ", "blue") + policy)
                return True
        print(colored(f"[✗] DMARC record not found for {domain}", "red"))
        return False
    except dns.resolver.NoAnswer:
        print(colored(f"[✗] DMARC record not found for {domain}", "red"))
        return False
    except Exception as e:
        print(colored(f"[-] DMARC check failed: {e}", "red"))
        return False

def check_spf(domain):
    """Check SPF record for the domain."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for record in answers:
            record_text = record.to_text().strip('"')
            if "v=spf1" in record_text:
                print(colored(f"[✓] SPF record found: {record_text}", "green"))
                return True
        print(colored(f"[✗] SPF record not found for {domain}", "red"))
        return False
    except dns.resolver.NoAnswer:
        print(colored(f"[✗] SPF record not found for {domain}", "red"))
        return False
    except Exception as e:
        print(colored(f"[-] SPF check failed: {e}", "red"))
        return False

def check_dkim(domain, selector="default"):
    """Check DKIM record for the domain."""
    try:
        answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
        for record in answers:
            record_text = record.to_text().strip('"')
            if "v=DKIM1" in record_text:
                print(colored(f"[✓] DKIM record found: {record_text}", "green"))
                return True
        print(colored(f"[✗] DKIM record not found for {domain}", "red"))
        return False
    except dns.resolver.NoAnswer:
        print(colored(f"[✗] DKIM record not found for {domain}", "red"))
        return False
    except Exception as e:
        print(colored(f"[-] DKIM check failed: {e}", "red"))
        return False

def main():
    while True:
        print(colored("""
        

########  ##     ##    ###    ########   ######  ##     ## 
##     ## ###   ###   ## ##   ##     ## ##    ##  ##   ##  
##     ## #### ####  ##   ##  ##     ## ##         ## ##   
##     ## ## ### ## ##     ## ########  ##          ###    
##     ## ##     ## ######### ##   ##   ##         ## ##   
##     ## ##     ## ##     ## ##    ##  ##    ##  ##   ##  
########  ##     ## ##     ## ##     ##  ######  ##     ## 
 
        """, 'green'))
        print(colored("\n=== DMARC, SPF & DKIM Checker by learnwithaq.com ===", "cyan", attrs=["bold"]))
        print("1. Check DMARC/SPF/DKIM Records")
        print("2. Exit")
        choice = input(colored("\nSelect an option (1/2): ", "yellow"))

        if choice == "1":
            domain = input("Enter the domain to check (e.g., example.com): ").strip()
            print(colored("\n[+] Checking Email Security Records:", "blue"))
            check_dmarc(domain)
            check_spf(domain)
            check_dkim(domain)
        elif choice == "2":
            print(colored("[+] Exiting the program. Goodbye!", "green"))
            break
        else:
            print(colored("[-] Invalid choice. Please select 1 or 2.", "red"))

if __name__ == "__main__":
    main()
