from datetime import datetime
import os, json, requests, argparse  # type: ignore
from rich.console import Console  # type: ignore
from rich.table import Table  # type: ignore
from rich.panel import Panel  # type: ignore
from dotenv import load_dotenv
import utils

load_dotenv()

PROXY_CHECK_URL = "https://proxycheck.io/v2/{{IP}}?vpn=1&asn=1"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
IPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
INPUT_PATH = "./input"
CACHE_MALICIOUS_PATH = "./ip_malevoli.json"
CACHE_BENIGN_PATH = "./ip_benigni.json"

MALEVOLI = []


VT_TOKEN = os.getenv("VIRUS_TOTAL_KEY")
IPDB_TOKEN =  os.getenv("ABUSEIPDB_KEY")

def salva_tutto(): 
        # 4) Salvo le cache aggiornate a fine esecuzione
    utils.save_ip_cache(CACHE_MALICIOUS_PATH, known_malicious)
    utils.save_ip_cache(CACHE_BENIGN_PATH, known_benign)

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
input = [args.IP] if args.IP != "" else utils.read_input_file()
verbose = args.nv

headers = (
    {"accept": "application/json", "x-apikey": VT_TOKEN}
    if VT_TOKEN is not None
    else {}
)

# Carica le cache esistenti
known_malicious = utils.load_ip_cache(CACHE_MALICIOUS_PATH)
known_benign = utils.load_ip_cache(CACHE_BENIGN_PATH)

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
        # richiesta virustotal
        response = requests.get(url, headers=headers)
        if utils.check_quota_exceeded_vt(response):
            print('Limite VirusTotal raggiunto. Blocco l\'esecuzione')
            salva_tutto()
            exit(1)
        # richiesta ipdb
        ipdbresponse = requests.get(url=IPDB_URL, 
                                  params={ 'ipAddress': ip, 'maxAgeInDays': '90'}, 
                                  headers={'Accept': 'application/json', 'Key': IPDB_TOKEN})
        if utils.check_quota_exceeded_vt(response):
            print('Limite AbuseIPDB raggiunto. Blocco l\'esecuzione')
            salva_tutto()
            exit(1)
        try:
            is_sus = utils.print_virustotal_response(
                response.json()["data"]["attributes"], print=not verbose
            ) and utils.check_abuse_ipdb(ipdbresponse.text)
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
        utils.print_proxycheck_responose(
            response[ip], is_ioc=is_sus, print=not verbose
        )
    except Exception:
        pass

    # 3) Aggiorno la cache in base all'esito
    if is_sus:
        known_malicious.add(ip)
    else:
        known_benign.add(ip)

salva_tutto()
# 5) Output finale
if len(MALEVOLI):
    print("\n".join(MALEVOLI))
else:
    print("nessun host è considerato malevolo")

