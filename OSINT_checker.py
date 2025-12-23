from datetime import datetime
import os, json, requests, argparse  # type: ignore
from rich.console import Console  # type: ignore
from rich.table import Table  # type: ignore
from rich.panel import Panel  # type: ignore
from dotenv import load_dotenv

load_dotenv()

PROXY_CHECK_URL = "https://proxycheck.io/v2/{{IP}}?vpn=1&asn=1"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
IPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
INPUT_PATH = "./input"
CACHE_MALICIOUS_PATH = "./ip_malevoli.json"
CACHE_BENIGN_PATH = "./ip_benigni.json"

MALEVOLI = []


def read_input_file():
    if not os.path.exists(INPUT_PATH):
        raise FileNotFoundError("File input non trovato")

    try:
        with open(INPUT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Verifica che sia una lista di stringhe (IP)
        if not isinstance(data, list) or not all(isinstance(ip, str) for ip in data):
            raise ValueError("Il file non contiene una lista valida di stringhe IP.")

        return data
    except Exception as e:
        raise ValueError(f"Errore nel parsing del file JSON: {e}")


def get_data_from_json(key: str, data: dict) -> str:
    try:
        return data.get(key)
    except Exception:
        return "-"

def check_abuse_ipdb(response:str): 
    decoded = json.loads(response)
    return int(decoded['data']['abuseConfidenceScore'])>1

def print_proxycheck_responose(data: dict, is_ioc: bool = False, print: bool = True):
    console = Console()

    table = Table(title="IP Analysis", show_lines=True)

    table.add_column("Categoria", style="bold cyan")
    table.add_column("Informazioni", style="white")

    table.add_row(
        "ASN / Org",
        f"{get_data_from_json('asn', data=data)} - {get_data_from_json('organisation', data=data)}",
    )
    table.add_row("Provider", get_data_from_json("provider", data=data))
    table.add_row(
        "Type / Proxy",
        f"{get_data_from_json('type', data=data)} / Proxy: {get_data_from_json('proxy', data=data)}",
    )
    table.add_row("Hostname", get_data_from_json("hostname", data=data))
    table.add_row(
        "Location",
        f"{get_data_from_json('city', data=data)}, "
        f"{get_data_from_json('region', data=data)} "
        f"({get_data_from_json('country', data=data)})",
    )
    table.add_row(
        "Coordinates",
        f"{get_data_from_json('latitude', data=data)}, {get_data_from_json('longitude', data=data)}",
    )
    table.add_row("Timezone", get_data_from_json("timezone", data=data))
    table.add_row("IP Range", get_data_from_json("range", data=data))

    if print:
        console.print(table)

        # Mostra se è IoC
        stringa = (
            "L'ip indicato non risulta essere malevolo nelle fonti OSINT analizzare"
            if not is_ioc
            else "L'ip indicato risulta essere malevolo"
        )
        console.print(
            Panel(f"→ {stringa}", style="bold red" if is_ioc else "bold green")
        )


def print_virustotal_response(data: dict, print: bool = True) -> bool:
    # ATTR_DA_GUARDARE = 'last_analysis_stats', 'last_analysis_date'
    analysis_stats = data.get("last_analysis_stats")
    last_date = data.get("last_analysis_date")
    console = Console()

    try:
        timestamp = datetime.fromtimestamp(last_date)
    except Exception:
        timestamp = None

    table = Table(
        title=f"VIRUS TOTAL (Last Analysis {timestamp})", show_lines=True
    )

    table.add_column("Status", style="bold red")
    table.add_column("Valore", style="white")

    for label, count in analysis_stats.items():
        color = "red" if label.lower() in ["malicious", "suspicious"] else "green"
        table.add_row(f"[{color}]{label.capitalize()}[/{color}]", str(count))

    if print:
        console.print(table)

    return analysis_stats["malicious"] > 0


def load_ip_cache(path: str) -> set:
    """Carica una lista di IP da file JSON e la restituisce come set."""
    if not os.path.exists(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return set(str(ip) for ip in data)
        return set()
    except Exception:
        return set()


def save_ip_cache(path: str, ip_set: set):
    """Salva un set di IP in un file JSON (lista ordinata)."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sorted(list(ip_set)), f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Errore nel salvataggio della cache {path}: {e}")


VT_TOKEN = os.getenv("VIRUS_TOTAL_KEY")
IPDB_TOKEN =  os.getenv("ABUSEIPDB_KEY")

parser = argparse.ArgumentParser(
    description="Analizza uno o più IP sulla base di diverse fonti OSINT"
)
parser.add_argument(
    "--IP",
    help="l'indirizzo IP da analizzare",
    required=False,
    default="",
    type=str,
)
parser.add_argument(
    "--nv",
    help="output non verboso, visualiza solo gl ip malevoli",
    default=False,
    required=False,
    action="store_true",
)

args = parser.parse_args()
input = [args.IP] if args.IP != "" else read_input_file()
verbose = args.nv

headers = (
    {"accept": "application/json", "x-apikey": VT_TOKEN}
    if VT_TOKEN is not None
    else {}
)

# Carica le cache esistenti
known_malicious = load_ip_cache(CACHE_MALICIOUS_PATH)
known_benign = load_ip_cache(CACHE_BENIGN_PATH)

for ip in input:
    ip = ip.strip()
    if not ip:
        continue

    is_sus = False  # default

    # 1) Controllo cache prima di fare richieste alle API
    if ip in known_malicious:
        is_sus = True
        MALEVOLI.append(ip)
        if not verbose:
            print(f"{ip} già noto come MALEVOLo (cache)")
        # Non interrogo le API se già noto
        continue
    elif ip in known_benign:
        if not verbose:
            print(f"{ip} già noto come NON malevolo (cache)")
        # Non interrogo le API se già noto
        continue

    # 2) IP non in cache → interrogo VirusTotal e ProxyCheck
    url = f"{VIRUSTOTAL_URL}{ip}"

    if VT_TOKEN is not None:
        response = requests.get(url, headers=headers)
        ipdbresponse = requests.get(url=IPDB_URL, 
                                  params={ 'ipAddress': ip, 'maxAgeInDays': '90'}, 
                                  headers={'Accept': 'application/json', 'Key': IPDB_TOKEN})
        try:
            is_sus = print_virustotal_response(
                response.json()["data"]["attributes"], print=not verbose
            ) and check_abuse_ipdb(ipdbresponse.text)
        except Exception:
            is_sus = False

        if is_sus:
            MALEVOLI.append(ip)
    else:
        # Se non ho VT, considero l'IP non malevolo ai fini della cache
        is_sus = False

    # ProxyCheck (non influenza la classificazione malevolo/non malevolo,
    # ma solo l'output informativo)
    try:
        response = requests.get(PROXY_CHECK_URL.replace("{{IP}}", ip)).json()
        print_proxycheck_responose(
            response[ip], is_ioc=is_sus, print=not verbose
        )
    except Exception:
        pass

    # 3) Aggiorno la cache in base all'esito
    if is_sus:
        known_malicious.add(ip)
    else:
        known_benign.add(ip)

# 4) Salvo le cache aggiornate a fine esecuzione
save_ip_cache(CACHE_MALICIOUS_PATH, known_malicious)
save_ip_cache(CACHE_BENIGN_PATH, known_benign)

# 5) Output finale
if len(MALEVOLI):
    print("\n".join(MALEVOLI))
else:
    print("nessun host è considerato malevolo")

