import utils

CACHE_MALICIOUS_PATH = "./ip_malevoli.json"
CACHE_BENIGN_PATH = "./ip_benigni.json"

input = utils.read_input_file()
known_malicious = utils.load_ip_cache(CACHE_MALICIOUS_PATH)
known_benign = utils.load_ip_cache(CACHE_BENIGN_PATH)


for ip in input:
    ip = ip.strip()
    if not ip:
        continue
    try: 
        known_malicious.add(ip)
        known_benign.remove(ip)
    except Exception:
        pass

utils.save_ip_cache(CACHE_MALICIOUS_PATH, known_malicious)
utils.save_ip_cache(CACHE_BENIGN_PATH, known_benign)
