from datetime import datetime
import os, json, requests, argparse # type: ignore
from rich.console import Console # type: ignore
from rich.table import Table # type: ignore
from rich.panel import Panel # type: ignore
from dotenv import load_dotenv

load_dotenv()
PROXY_CHECK_URL = 'https://proxycheck.io/v2/{{IP}}?vpn=1&asn=1'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
INPUT_PATH = './input'

def read_input_file():
    
    if not os.path.exists(INPUT_PATH):
        raise  print('File input non trovato')
    
    try:
        with open(INPUT_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Verifica che sia una lista di stringhe (IP)
        if not isinstance(data, list) or not all(isinstance(ip, str) for ip in data):
            raise ValueError('Il file non contiene una lista valida di stringhe IP.')

        return data
    except json.JSONDecoderError as e:
        raise ValueError(f'Errore nel parsing del file JSON: {e}')

def get_data_from_json(key: str, data: dict)->str:
    try:
        return data.get(key)
    except Exception as e:
        return '-'


def print_proxycheck_responose(data: dict, is_ioc: bool = False):
    console = Console()
    
    table = Table(title='IP Analysis', show_lines=True)

    table.add_column('Categoria', style='bold cyan')
    table.add_column('Informazioni', style='white')

    table.add_row('ASN / Org', f'{get_data_from_json('asn', data=data)} - {get_data_from_json('organisation', data=data)}')
    table.add_row('Provider', get_data_from_json('provider', data=data))
    table.add_row('Type / Proxy', f'{get_data_from_json('type', data=data)} / Proxy: {get_data_from_json('proxy', data=data)}')
    table.add_row('Hostname', get_data_from_json('hostname', data=data))
    table.add_row('Location', f'{get_data_from_json('city', data=data)}, {get_data_from_json('region', data=data)} ({get_data_from_json('country', data=data)})')
    table.add_row('Coordinates', f'{get_data_from_json('latitude', data=data)}, {get_data_from_json('longitude', data=data)}')
    table.add_row('Timezone', get_data_from_json('timezone', data=data))
    table.add_row('IP Range', get_data_from_json('range', data=data))

    console.print(table)

    # Mostra se è IoC
    stringa = 'L\'ip indicato non risulta essere malevolo nelle fonti OSINT analizzare' if not is_ioc else 'L\'ip indicato risulta essere malevolo'
    console.print(Panel(f'→ {stringa}',  style='bold red' if is_ioc else 'bold green'))

def print_virustotal_response(data:dict) -> bool:
    # ATTR_DA_GUARDARE = 'last_analysis_stats', 'last_analysis_date'
    analysis_stats = data.get('last_analysis_stats')
    last_date = data.get('last_analysis_date')
    console = Console()

    try:
        timestamp = datetime.fromtimestamp(last_date)
    except Exception:

        timestamp = None

    table = Table(title=f'VIRUS TOTAL (Last Analysis {timestamp})', show_lines=True)

    table.add_column('Status', style='bold red')
    table.add_column('Valore', style='white')

    for label, count in analysis_stats.items():
        color = 'red' if label.lower() in ['malicious', 'suspicious'] else 'green'
        table.add_row(f'[{color}]{label.capitalize()}[/{color}]', str(count))

    console.print(table)

    return analysis_stats['malicious'] > 0

VT_TOKEN = os.getenv("VIRUS_TOTAL_KEY")
parser = argparse.ArgumentParser(description='Analizza uno o più IP sulla base di diverse fonti OSINT')
parser.add_argument('IP', help='l\'indirizzo IP da analizzare', default='', nargs='?')

args = parser.parse_args()
input = [args.IP] if args.IP != '' else read_input_file()


headers = {'accept': 'application/json', 'x-apikey':VT_TOKEN} if VT_TOKEN is not None else {}
print(input)
for ip in input:
    url = f'{VIRUSTOTAL_URL}{ip}'

    if VT_TOKEN is not None:
        response = requests.get(url, headers=headers)
        is_sus = print_virustotal_response(response.json()['data']['attributes'])
    response = requests.get(PROXY_CHECK_URL.replace('{{IP}}', ip)).json()
    print_proxycheck_responose(response[ip], is_ioc=is_sus)

