# WAF za Command Injection

Projekat za kurs Bezbednost veb servisa. Ideja je da se napravi jednostavan WAF middleware u Flasku koji štiti aplikaciju od command injection napada.

## O čemu se radi

Command injection je napad gde napadač ubaci OS komandu kroz korisnički unos. Na primer, ako aplikacija radi `ping <host>` i ne sanitizuje unos, neko može da pošalje `google.com; cat /etc/passwd` i dobije sadržaj sistemskog fajla. OWASP ga svrstava u A03:2021 – Injection.

Projekat ima dve verzije Flask aplikacije:
- `app.py` – namerno ranjiva, bez ikakve zaštite (pokrenuti na portu 5000)
- `app_protected.py` – ista aplikacija ali sa WAF-om (port 5001)

WAF logika je u `waf.py`, a testovi u `test_payloads.py`.

## Instalacija

```bash
pip install -r requirements.txt
```

## Pokretanje

```bash
# ranjiva verzija
python app.py

# zasticena verzija
python app_protected.py
```

Upozorenje: ranjiva aplikacija je namerno nesigurna, pokretati samo lokalno.

## Kako WAF radi

WAF se zakači kao `before_request` hook u Flasku i svaki zahtev prođe kroz 4 sloja pre nego što stigne do rute:

1. **Whitelist** – za parametre kao što je `host`, proverava se da li vrednost odgovara regex-u koji dozvoljava samo hostname/IP format. Sve ostalo odmah pada.

2. **Blacklista karaktera** – traži shell operatore: `;`, `&&`, `||`, `|`, backtick, `$(`, `${`, newline, redirect operatore...

3. **Blacklista ključnih reči** – traži komande i putanje koje ne bi trebalo da se nađu u parametrima: `cat`, `whoami`, `wget`, `/etc/passwd`, `/bin/` i slično.

4. **Regex obrasci** – hvata naprednije tehnike zaobilaženja kao što su command substitution `$(...)`, backtick izvršavanje, hex i URL enkodiranje.

Kada WAF uhvati napad, vraća 403 sa JSON-om koji kaže zašto je blokiran i upisuje u `waf.log`.

## Testiranje

```bash
python test_payloads.py
```

Skripta testira 10 napadnih payloada i 3 legitimna zahteva i ispisuje koji su prošli a koji nisu.

## Grane

- `main` – ranjiva aplikacija bez zaštite
- `protection` – aplikacija sa WAF-om

## Napomena

Ovo je demonstracija koncepta. U produkciji bi trebalo koristiti `subprocess` sa listom argumenata umesto `shell=True` (to je pravi fix), plus zrela WAF rešenja kao ModSecurity. Ovaj WAF ne pokriva HTTP body, samo GET parametre, i ranjiv je na napredne tehnike enkodiranja.
