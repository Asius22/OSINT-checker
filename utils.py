from datetime import datetime
import os, json, requests, argparse  # type: ignore
from rich.console import Console  # type: ignore
from rich.table import Table  # type: ignore
from rich.panel import Panel  # type: ignore
from dotenv import load_dotenv


PROXY_CHECK_URL = "https://proxycheck.io/v2/{{IP}}?vpn=1&asn=1"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
IPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
INPUT_PATH = "./input"
CACHE_MALICIOUS_PATH = "./ip_malevoli.json"
CACHE_BENIGN_PATH = "./ip_benigni.json"

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

import sys
import requests

def _die(msg: str) -> None:
    print(msg)
    sys.exit(1)

def _fmt_http_error(service: str, resp: requests.Response) -> str:
    # prova a mostrare anche un messaggio "utile" dal body
    body_preview = ""
    try:
        j = resp.json()
        # VirusTotal spesso: {"error": {"code": "...", "message": "..."}}
        if isinstance(j, dict):
            if "error" in j and isinstance(j["error"], dict):
                code = j["error"].get("code")
                message = j["error"].get("message")
                body_preview = f" | body.error.code={code} body.error.message={message}"
            # AbuseIPDB: {"errors":[{"detail":"...","status":429}]}
            elif "errors" in j and isinstance(j["errors"], list) and j["errors"]:
                detail = j["errors"][0].get("detail")
                status = j["errors"][0].get("status")
                body_preview = f" | body.errors[0].status={status} body.errors[0].detail={detail}"
    except Exception:
        # body non-JSON (es. HTML), ignoriamo
        pass

    retry_after = resp.headers.get("Retry-After")
    ra = f" | Retry-After={retry_after}s" if retry_after else ""
    return f"[ERRORE {service}] HTTP {resp.status_code}{ra}{body_preview}"

def check_quota_exceeded_vt(resp: requests.Response) -> bool:
    # VT: quota/rate limit -> 429 (v3) oppure 204 (v2/legacy) :contentReference[oaicite:3]{index=3}
    if resp.status_code in (204, 429):
        # _die(_fmt_http_error("VirusTotal QUOTA/RATE-LIMIT", resp))
        return True
    # In alcuni casi VT risponde 429 con JSON "QuotaExceededError" :contentReference[oaicite:4]{index=4}
    try:
        j = resp.json()
        if isinstance(j, dict) and "error" in j and isinstance(j["error"], dict):
            code = str(j["error"].get("code", "")).lower()
            msg = str(j["error"].get("message", "")).lower()
            if "quota" in code or "quota" in msg or "rate" in msg:
                return True
                # _die(_fmt_http_error("VirusTotal QUOTA/RATE-LIMIT", resp))
    except Exception:
        return False

def check_quota_exceeded_abuseipdb(resp: requests.Response) -> None:
    # AbuseIPDB: daily limit -> 429 :contentReference[oaicite:5]{index=5}
    if resp.status_code == 429:
        # _die(_fmt_http_error("AbuseIPDB QUOTA/RATE-LIMIT", resp))
        return True
    # Extra-sicurezza: se headers dicono remaining=0, consideralo errore hard.
    # (doc segnala che i dettagli sono nei headers) :contentReference[oaicite:6]{index=6}
    remaining = resp.headers.get("X-RateLimit-Remaining")
    if remaining is not None:
        try:
            if int(remaining) <= 0:
                # _die(_fmt_http_error("AbuseIPDB QUOTA (X-RateLimit-Remaining=0)", resp))
                return True
        except ValueError:
            pass
