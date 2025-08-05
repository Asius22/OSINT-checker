import requests  # type: ignore
from datetime import datetime

from rich.console import Console # type: ignore
from rich.table import Table # type: ignore
from rich.panel import Panel # type: ignore

PROXY_CHECK_URL = 'https://proxycheck.io/v2/{{IP}}?vpn=1&asn=1'

def print_proxycheck_responose(data: dict, is_ioc: bool = False):
    console = Console()
    
    table = Table(title="IP Analysis", show_lines=True)

    table.add_column("Categoria", style="bold cyan")
    table.add_column("Informazioni", style="white")

    table.add_row("ASN / Org", f"{data.get('asn')} - {data.get('organisation')}")
    table.add_row("Provider", data.get("provider"))
    table.add_row("Type / Proxy", f"{data.get('type')} / Proxy: {data.get('proxy')}")
    table.add_row("Hostname", data.get("hostname"))
    table.add_row("Location", f"{data.get('city')}, {data.get('region')} ({data.get('country')})")
    table.add_row("Coordinates", f"{data.get('latitude')}, {data.get('longitude')}")
    table.add_row("Timezone", data.get("timezone"))
    table.add_row("IP Range", data.get("range"))

    console.print(table)

    # Mostra se è IoC
    stringa = "L'ip indicato non risulta essere malevolo nelle fonti OSINT analizzare" if not is_ioc else "L'ip indicato risulta essere malevolo"
    console.print(Panel(f"→ {stringa}",  style="bold red" if is_ioc else "bold green"))

def print_virustotal_response(data:dict) -> bool:
    # ATTR_DA_GUARDARE = 'last_analysis_stats', 'last_analysis_date'
    analysis_stats = data['last_analysis_stats']
    last_date = data['last_analysis_date']
    console = Console()

    try:
        timestamp = datetime.fromtimestamp(last_date)
    except Exception:

        timestamp = None

    table = Table(title=f"VIRUS TOTAL (Last Analysis {timestamp})", show_lines=True)

    table.add_column("Status", style="bold red")
    table.add_column("Valore", style="white")

    for label, count in analysis_stats.items():
        color = 'red' if label.lower() in ['malicious', 'suspicious'] else 'green'
        table.add_row(f"[{color}]{label.capitalize()}[/{color}]", str(count))

    console.print(table)

    return analysis_stats['malicious'] > 0


ip = "185.220.101.1"

url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

headers = {"accept": "application/json", "x-apikey":"738a31a39ac78ea4cc5d2d9599631963f583024ddafc4e0aab5d1e8f97e491e5"}

response = requests.get(url, headers=headers)
is_sus = print_virustotal_response(response.json()['data']['attributes'])
response = requests.get(PROXY_CHECK_URL.replace('{{IP}}', ip)).json()
print_proxycheck_responose(response[ip], is_ioc=is_sus)