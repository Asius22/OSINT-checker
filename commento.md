### Descrizione:

L’incident in questione rileva un numero eccessivo di connessioni fallite (≥5000) in un intervallo temporale di 5 minuti da parte un indirizzo IP privato verso IP esterni.

### Triage

Da analisi effettuata si evidenzia che i seguenti indirizzi IP privati. ["10.76.0.70","10.30.1.135","10.35.11.43","10.150.48.96","10.150.63.161","10.150.63.128","10.150.63.94","10.150.8.176","52.112.235.72","10.145.6.11","10.150.8.42","10.255.254.85"] abbiano effettuato molteplici tentativi falliti di connessione verso molteplici indirizzi.

Nello specifico:

- si riscontrano circa 1740000 richieste fallite su porta 53 verso 30 indirizzi IP esterni. le richieste sono prevalentemente in deny. NOn si riscontrano richieste verso indirizzi IP malevoli. si riscontra un picco di richieste il 3/8/2026. Il picco risulta essere da parte dell'indirizzo IP interno 10.76.0.70 verso gli indirizzi [1.1.1.1, 1.0.0.1]. l'attività ha inizio il 31/7/2026
- si riscontrano circa 1.090.000 richieste fallite su porta 443 verso 1386 indirizzi IP esterni. le richieste sono prevalentemente in blocked/deny. analizzando le richieste NON in deny NON si riscontrano richieste verso indirizzi IP malevoli. le richieste risultano prevalentemente da parte degli indirizzi  ["10.30.1.135","10.35.11.43"]. l'attività è stata segnalata con incident ID 36914. si procede con la correlazione

```jsx
let src = dynamic();
CommonSecurityLog
| where DeviceAction !in ("accept", "pass", "pssthrough", "ip-conn", "close")// | where DestinationPort < 10000
| where TimeGenerated > ago(1d)
| where SourceIP has_any (src)
| summarize 
    Fallimenti=count(),
    Sorgenti=make_set(SourceIP),
    Interni=make_set_if(DestinationIP, ipv4_is_private(DestinationIP)),
    Esterni= make_set_if(DestinationIP, not(ipv4_is_private(DestinationIP)))
    by DestinationPort
```

### Escalation:

Dato che le connessioni verso gli ip esterni risultano fallite. su porte note si procede a chiudere l’incident come Benign Positive.