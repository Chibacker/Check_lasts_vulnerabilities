from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
import xml.etree.ElementTree as ET
import urllib.request
from datetime import *
import ssl

console = Console()
how_many_days_to_retrieve = 7


def menu():
    console.rule("[bold Yellow]MENU[/]")
    console.print("options :")
    console.print(" [0] : EXIT")
    console.print(" [1] : Show last vulnerabilities")
    console.print("")
    x = input('Select option number : ')
    return x

def get_vulns():
    console.rule("[bold Yellow]List CVE in cert.ssi.gouv.fr[/]")
    url = 'https://www.cert.ssi.gouv.fr/feed/'
    ssl._create_default_https_context = ssl._create_unverified_context
    response = urllib.request.urlopen(url).read()
    root = ET.fromstring(response)
    vulns = []
    for item in root.findall('channel/item'):
        try:
            item_title = item[0].text
            item_link = item[1].text
            item_pubdate = item[2].text
            item_description = item[4].text
            item_array = [item_pubdate, item_title, item_link, item_description]
            last_days = datetime.now(timezone.utc) + timedelta(days=-how_many_days_to_retrieve)
            pubdate = datetime.strptime(item[2].text, "%a, %d %b %Y %H:%M:%S %z")
            if pubdate >= last_days:
                vulns.append(item_array)
        except Exception as e:
            print(str(e))
            pass
    return vulns


def main():
    console.print(Markdown("# CHECK VULNERABILITIES"))
    while True :
        option = menu()
        if option == "0":
            exit(0)
        elif option == "1":
            vulns = get_vulns()
            table = Table()
            table.add_column("Name")
            table.add_column("Date")
            table.add_column("Link")
            for vuln in vulns:
                table.add_row(vuln[1], vuln[0], vuln[2])
            console.print(table)
        else:
            console.print("[bold red]Bad argument...[/]")



main()