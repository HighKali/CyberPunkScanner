# CyberPunkScanner

**CyberPunkScanner** è un toolkit di information gathering, port scanning e automazione OSINT in puro stile cyberpunk terminale, con UI colorata, ASCII art e automazioni "magiche".

---

## Funzionalità principali

- **OSINT scan**: WHOIS, DNS, subdomini comuni
- **MagicNmap+**: Scansione porte TCP/UDP in multithreading, banner grabbing, servizio guessing, risk hints
- **Port scan personalizzato**: TCP/UDP, banner grab opzionale, intervallo porte custom
- **HTTP header analysis**
- **Banner grab**
- **Geolocalizzazione IP/IPv6**
- **Check IPv6**
- **Server/device fingerprinting**
- **Traceroute magico** (senza dipendenze esterne)
- **Auto Recon**: Tutte le funzioni in sequenza, automagicamente!
- **Report**: TXT/JSON, timestamp su ogni azione
- **UI cyberpunk** (colori, ASCII, animazioni)
- **Menu interattivo e smart**

---

## Installazione

1. Installa le dipendenze:
   ```bash
   sudo apt update
   sudo apt install python3-pip
   pip3 install -r requirements.txt
   ```

2. Avvia il tool:
   ```bash
   python3 cyberpunkscanner.py
   ```

---

## Note importanti

- **Usa solo su target autorizzati!**
- Per funzionalità raw socket (traceroute) serve permesso root/sudo o capacità di usare socket RAW.
- I report vengono salvati nella directory di lavoro.

---

## Magia extra

- MagicNmap+ riconosce rischi e ti avvisa di porte critiche
- Automazione completa OSINT+scan+fingerprint+traceroute+report con [9]
- UI animata e colori per hacking cinematografico!

---

Enjoy!
