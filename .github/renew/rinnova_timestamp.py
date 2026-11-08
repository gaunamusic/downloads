#!/usr/bin/env python3
"""
rinnova_timestamp.py — rifirma il solo timestamp dell'indice dei programmi e lo sostituisce senza perdere il file.

Gira dentro GitHub Actions, in due lavori separati (`.github/workflows/rinnova-timestamp.yml`):

    python3 -I rinnova_timestamp.py firma       # ha la chiave del timestamp e un gettone di sola lettura
    python3 -I rinnova_timestamp.py pubblica    # ha il gettone che scrive, e non ha la chiave

PERCHÉ DUE LAVORI. Il passo che tiene la chiave non può scrivere sul repo, e quello che scrive non ha la chiave.

PERCHÉ NIENTE DIPENDENZE. Nel processo che tiene la chiave c'è soltanto la libreria standard di Python e `openssl` del runner:
ogni pacchetto in più avrebbe accesso alla chiave. La firma è Ed25519 sul JSON canonico del campo `signed` (The Update Framework,
§ «Object format»), e il banco la confronta, byte per byte, con quella di `python-tuf` sugli stessi dati.

COSA RIFIRMA. Copia il timestamp che c'è e cambia solo `version` (più uno) e `expires`: lo snapshot a cui punta resta quello
pubblicato. Chi ruba questa chiave può far aspettare i programmi su uno stato vecchio, ma non può farne installare uno nuovo:
i programmi li firmano altre chiavi, che qui non ci sono.

LA CHIAVE NON SI STAMPA. Arriva dall'ambiente, va a `openssl` su stdin, non passa dal disco né dalla riga di comando, e nessun
messaggio d'errore la contiene.

IL CAMBIO DEL FILE. `gh release upload --clobber` cancella e poi carica: se il caricamento fallisce il file è perso. Qui il file
nuovo si carica sotto un altro nome, si rilegge, e solo allora si scambiano i nomi; un guasto a metà rimette il file di prima, e
una corsa morta a metà la ripara la corsa dopo.
"""

import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

TAG = "metadata"
NOME, NUOVO, VECCHIO = "timestamp.json", "timestamp.json.nuovo", "timestamp.json.vecchio"
DURATA_GIORNI = 7                # quanto vale un timestamp firmato
MARGINE_SCADENZE_GIORNI = 14     # sotto questo margine snapshot, targets e root fanno diventare rossa la corsa
GIORNI_SENZA_COMMIT = 40         # GitHub spegne i lavori pianificati di un repo pubblico fermo da 60 giorni
RAMO = "main"
OPENSSL = os.environ.get("GC_OPENSSL", "openssl")


class Fermo(Exception):
    """Un motivo per fermarsi, scritto per essere stampato: non contiene mai la chiave. `codice` è lo stato HTTP, se c'è."""

    def __init__(self, messaggio, codice=None):
        super().__init__(messaggio)
        self.codice = codice


# ---------------------------------------------------------------------------
# IL FORMATO DI TUF

def canonico(x):
    """Il JSON canonico (specifica TUF, § «File formats: general principles»), come lo scrive `securesystemslib`."""
    if isinstance(x, str):
        return '"' + x.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if x is True:
        return "true"
    if x is False:
        return "false"
    if x is None:
        return "null"
    if isinstance(x, int):
        return str(x)
    if isinstance(x, list):
        return "[" + ",".join(canonico(v) for v in x) + "]"
    if isinstance(x, dict):
        return "{" + ",".join(canonico(k) + ":" + canonico(x[k]) for k in sorted(x)) + "}"
    raise Fermo(f"nel timestamp c'è un valore che il JSON canonico non ammette: {type(x).__name__}")


def in_byte(signed):
    return canonico(signed).encode("utf-8")


def data(istante):
    return istante.astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def leggi_data(testo):
    return dt.datetime.strptime(testo, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def file_del_timestamp(signed, keyid, firma_hex):
    """I byte del file, nella forma in cui `python-tuf` lo scrive (rientro 1, chiavi ordinate)."""
    return json.dumps({"signatures": [{"keyid": keyid, "sig": firma_hex}], "signed": signed}, indent=1, sort_keys=True).encode("utf-8")


def chiave_del_ruolo(root):
    """(keyid, pubblica in esadecimale) della chiave del timestamp: una sola, Ed25519, soglia 1. Altrimenti ci si ferma."""
    ruolo = root["roles"]["timestamp"]
    if ruolo["threshold"] != 1 or len(ruolo["keyids"]) != 1:
        raise Fermo("il ruolo timestamp della root non è una chiave sola con soglia 1: questo programma non sa firmarlo")
    keyid = ruolo["keyids"][0]
    chiave = root["keys"][keyid]
    if chiave.get("keytype") != "ed25519" or chiave.get("scheme") != "ed25519":
        raise Fermo("la chiave del timestamp nella root non è Ed25519")
    return keyid, chiave["keyval"]["public"]


# ---------------------------------------------------------------------------
# OPENSSL: la chiave gli arriva su stdin

def _openssl(*argomenti, entrata=None):
    try:
        return subprocess.run([OPENSSL, *argomenti], input=entrata, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        raise Fermo("openssl non si lancia") from None


def pubblica_di(chiave_pem):
    p = _openssl("pkey", "-in", "/dev/stdin", "-pubout", "-outform", "DER", entrata=chiave_pem)
    if p.returncode != 0 or len(p.stdout) < 32:
        raise Fermo("il segreto non è una chiave privata che openssl sa leggere")
    return p.stdout[-32:].hex()


def firma(dati, chiave_pem):
    with tempfile.TemporaryDirectory() as d:
        messaggio, uscita = os.path.join(d, "m"), os.path.join(d, "s")
        with open(messaggio, "wb") as f:
            f.write(dati)
        p = _openssl("pkeyutl", "-sign", "-rawin", "-inkey", "/dev/stdin", "-in", messaggio, "-out", uscita, entrata=chiave_pem)
        if p.returncode != 0:
            raise Fermo("openssl non ha firmato")
        with open(uscita, "rb") as f:
            return f.read().hex()


def verifica(dati, firma_hex, pubblica_hex):
    """Vero se la firma è di quella chiave. La chiave pubblica è la `SubjectPublicKeyInfo` di RFC 8410 scritta a mano."""
    spki = bytes.fromhex("302a300506032b6570032100" + pubblica_hex)
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki) + b"\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as d:
        messaggio, firma_file = os.path.join(d, "m"), os.path.join(d, "s")
        with open(messaggio, "wb") as f:
            f.write(dati)
        with open(firma_file, "wb") as f:
            f.write(bytes.fromhex(firma_hex))
        p = _openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", "/dev/stdin", "-in", messaggio, "-sigfile", firma_file, entrata=pem)
    return p.returncode == 0


def controlla_firma(documento, keyid, pubblica_hex):
    for voce in documento.get("signatures", []):
        if voce.get("keyid") == keyid:
            try:
                if verifica(in_byte(documento["signed"]), voce["sig"], pubblica_hex):
                    return True
            except ValueError:
                pass
    return False


# ---------------------------------------------------------------------------
# GITHUB: solo le chiamate che servono

class _Rinvio(urllib.request.HTTPRedirectHandler):
    """Il file di un asset sta su un altro server, che non vuole il gettone di GitHub (e non deve riceverlo)."""

    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        nuova = super().redirect_request(req, fp, code, msg, hdrs, newurl)
        if nuova is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            nuova.remove_header("Authorization")
        return nuova


class Api:
    def __init__(self, repo, gettone, base="https://api.github.com"):
        self.repo, self.gettone, self.base = repo, gettone, base.rstrip("/")
        self.apri = urllib.request.build_opener(_Rinvio()).open

    def _chiama(self, metodo, url, corpo=None, tipo="application/json", accetta="application/vnd.github+json"):
        if not url.startswith("http"):
            url = self.base + url
        intestazioni = {"Accept": accetta, "User-Agent": "renew-timestamp", "X-GitHub-Api-Version": "2022-11-28"}
        if self.gettone:
            intestazioni["Authorization"] = f"Bearer {self.gettone}"
        if corpo is not None:
            intestazioni["Content-Type"] = tipo
        tentativi = 3 if metodo == "GET" else 1
        for n in range(tentativi):
            richiesta = urllib.request.Request(url, data=corpo, headers=intestazioni, method=metodo)
            try:
                with self.apri(richiesta, timeout=60) as r:
                    return r.read()
            except urllib.error.HTTPError as e:
                if e.code < 500 or n == tentativi - 1:
                    raise Fermo(f"GitHub ha risposto {e.code} a {metodo} {urllib.parse.urlsplit(url).path}", e.code) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if n == tentativi - 1:
                    raise Fermo(f"GitHub non risponde a {metodo} {urllib.parse.urlsplit(url).path}") from None
            time.sleep(2 * (n + 1))

    def _json(self, metodo, url, valore=None):
        corpo = None if valore is None else json.dumps(valore).encode("utf-8")
        testo = self._chiama(metodo, url, corpo)
        return json.loads(testo) if testo else None

    def leggi(self, percorso, accetta="application/vnd.github+json"):
        """Una lettura qualunque dell'API. `None` se la cosa non c'è (404)."""
        try:
            testo = self._chiama("GET", percorso, accetta=accetta)
        except Fermo as e:
            if e.codice == 404:
                return None
            raise
        return json.loads(testo) if accetta.endswith("github+json") else testo

    def stato(self):
        """(release, {nome: asset}) della release dei metadati, letti dall'API e non dall'indirizzo pubblico, che ha la cache."""
        rel = self._json("GET", f"/repos/{self.repo}/releases/tags/{TAG}")
        return rel, {a["name"]: a for a in rel["assets"]}

    def scarica(self, asset):
        return self._chiama("GET", f"/repos/{self.repo}/releases/assets/{asset['id']}", accetta="application/octet-stream")

    def carica(self, release, nome, dati):
        url = release["upload_url"].split("{")[0] + "?name=" + urllib.parse.quote(nome)
        return json.loads(self._chiama("POST", url, dati))

    def rinomina(self, asset_id, nome):
        self._json("PATCH", f"/repos/{self.repo}/releases/assets/{asset_id}", {"name": nome})

    def togli(self, asset_id):
        self._chiama("DELETE", f"/repos/{self.repo}/releases/assets/{asset_id}")

    def ultimo_commit(self):
        return self._json("GET", f"/repos/{self.repo}/commits?per_page=1&sha={RAMO}")[0]

    def commit_vuoto(self, ultimo, messaggio):
        """Un commit senza modifiche: stesso albero, un padre. Ciò che tiene acceso il lavoro pianificato."""
        nuovo = self._json("POST", f"/repos/{self.repo}/git/commits",
                           {"message": messaggio, "tree": ultimo["commit"]["tree"]["sha"], "parents": [ultimo["sha"]]})
        self._json("PATCH", f"/repos/{self.repo}/git/refs/heads/{RAMO}", {"sha": nuovo["sha"]})
        return nuovo["sha"]


# ---------------------------------------------------------------------------
# I DUE PASSI

def root_piu_recente(api, assets):
    numeri = [int(m.group(1)) for m in (re.fullmatch(r"(\d+)\.root\.json", n) for n in assets) if m]
    if not numeri:
        raise Fermo("nella release non c'è nessuna root")
    return json.loads(api.scarica(assets[f"{max(numeri)}.root.json"]))["signed"]


def rifirma(api, chiave_pem, adesso):
    """I byte del timestamp nuovo. Si ferma se il segreto non è la chiave del ruolo, o se il timestamp sul web non è valido."""
    _, assets = api.stato()
    corrente_asset = assets.get(NOME) or assets.get(VECCHIO)
    if corrente_asset is None:
        raise Fermo("nella release non c'è il timestamp")
    keyid, pubblica = chiave_del_ruolo(root_piu_recente(api, assets))
    if pubblica_di(chiave_pem) != pubblica:
        raise Fermo("il segreto non è la chiave del timestamp che la root dichiara: non si firma niente")
    corrente = json.loads(api.scarica(corrente_asset))
    if not controlla_firma(corrente, keyid, pubblica):
        raise Fermo("il timestamp sul web non è firmato dalla chiave della root: non lo si estende")
    if corrente["signed"].get("_type") != "timestamp":
        raise Fermo("il file sul web non è un timestamp")
    nuovo = dict(corrente["signed"])
    nuovo["version"] = corrente["signed"]["version"] + 1
    nuovo["expires"] = data(adesso + dt.timedelta(days=DURATA_GIORNI))
    byte_firmati = in_byte(nuovo)
    firma_hex = firma(byte_firmati, chiave_pem)
    if not verifica(byte_firmati, firma_hex, pubblica):
        raise Fermo("la firma appena fatta non si verifica con la chiave della root")
    return file_del_timestamp(nuovo, keyid, firma_hex)


def _riordina_i_resti(api, rel, assets, avvisi):
    """Una corsa morta a metà può aver lasciato il timestamp sotto un altro nome: prima di tutto si rimette a posto."""
    if NOME not in assets and VECCHIO in assets:
        api.rinomina(assets[VECCHIO]["id"], NOME)
        avvisi.append(f"il timestamp stava sotto il nome {VECCHIO}: rimesso a posto")
        rel, assets = api.stato()
    for resto in (NUOVO, VECCHIO):
        if resto in assets:
            api.togli(assets[resto]["id"])
            avvisi.append(f"tolto {resto}, rimasto da una corsa di prima")
    if NUOVO in assets or VECCHIO in assets:
        rel, assets = api.stato()
    return rel, assets


def sostituisci(api, dati, avvisi):
    """Il cambio. Vero se il file è stato sostituito, Falso se nel frattempo il timestamp sul web è cambiato e questo è superato.
    Il file di prima resta al suo posto finché quello nuovo non c'è ed è stato riletto."""
    documento = json.loads(dati)
    rel, assets = api.stato()
    rel, assets = _riordina_i_resti(api, rel, assets, avvisi)
    if NOME not in assets:
        raise Fermo("nella release non c'è il timestamp da sostituire")
    keyid, pubblica = chiave_del_ruolo(root_piu_recente(api, assets))
    if not controlla_firma(documento, keyid, pubblica):
        raise Fermo("il timestamp da pubblicare non è firmato dalla chiave della root: non si pubblica")
    corrente = json.loads(api.scarica(assets[NOME]))
    if corrente["signed"]["version"] + 1 != documento["signed"]["version"] or corrente["signed"]["meta"] != documento["signed"]["meta"]:
        avvisi.append(f"il timestamp sul web è cambiato mentre si firmava (ora è il v{corrente['signed']['version']}): questa firma è superata e non si pubblica")
        return False
    vecchio_id = assets[NOME]["id"]
    caricato = api.carica(rel, NUOVO, dati)
    try:
        if api.scarica(caricato) != dati:
            raise Fermo("il file caricato, riletto, non è quello firmato")
        api.rinomina(vecchio_id, VECCHIO)
    except Fermo:
        _togli_in_silenzio(api, caricato["id"])
        raise
    try:
        api.rinomina(caricato["id"], NOME)
    except Fermo:
        api.rinomina(vecchio_id, NOME)
        _togli_in_silenzio(api, caricato["id"])
        raise
    try:
        api.togli(vecchio_id)
    except Fermo as e:
        avvisi.append(f"il timestamp è sostituito, ma il file di prima è rimasto come {VECCHIO}: {e}")
    return True


def _togli_in_silenzio(api, asset_id):
    try:
        api.togli(asset_id)
    except Fermo:
        pass


def scadenze_vicine(api, adesso):
    """I ruoli che questa automazione non può rinnovare (snapshot, targets, root) e che scadono entro il margine. Il timestamp
    punta a loro: quando scadono, un timestamp valido non basta più."""
    _, assets = api.stato()
    timestamp = json.loads(api.scarica(assets[NOME]))["signed"]
    v_snapshot = timestamp["meta"]["snapshot.json"]["version"]
    snapshot = json.loads(api.scarica(assets[f"{v_snapshot}.snapshot.json"]))["signed"]
    v_targets = snapshot["meta"]["targets.json"]["version"]
    targets = json.loads(api.scarica(assets[f"{v_targets}.targets.json"]))["signed"]
    root = root_piu_recente(api, assets)
    guai = []
    for ruolo, firmato in (("snapshot", snapshot), ("targets", targets), ("root", root)):
        restano = leggi_data(firmato["expires"]) - adesso
        if restano < dt.timedelta(days=MARGINE_SCADENZE_GIORNI):
            guai.append(f"{ruolo} scade il {firmato['expires']}: questa automazione non può rifirmarlo, serve un caricamento dal Mac")
    return guai


def tieni_acceso(api, adesso, avvisi):
    """GitHub spegne i lavori pianificati di un repo pubblico senza attività da 60 giorni. Se il repo è fermo da troppo, un commit vuoto."""
    ultimo = api.ultimo_commit()
    data_ultimo = dt.datetime.fromisoformat(ultimo["commit"]["committer"]["date"].replace("Z", "+00:00"))
    if adesso - data_ultimo >= dt.timedelta(days=GIORNI_SENZA_COMMIT):
        sha = api.commit_vuoto(ultimo, "Keep the scheduled timestamp renewal active")
        avvisi.append(f"il repo era fermo da {(adesso - data_ultimo).days} giorni: commit vuoto {sha[:12]}, perché GitHub non spenga il lavoro pianificato")


# ---------------------------------------------------------------------------
# DA GITHUB ACTIONS

def _api():
    repo, gettone = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GH_TOKEN")
    if not repo or not gettone:
        raise Fermo("mancano GITHUB_REPOSITORY o GH_TOKEN")
    return Api(repo, gettone, os.environ.get("GC_API", "https://api.github.com"))


def comando_firma():
    chiave = os.environ.pop("TUF_TIMESTAMP_KEY", "").encode("utf-8")
    if not chiave:
        raise Fermo("manca il segreto con la chiave del timestamp")
    dati = rifirma(_api(), chiave, dt.datetime.now(dt.timezone.utc))
    versione = json.loads(dati)["signed"]["version"]
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        f.write(f"timestamp={base64.b64encode(dati).decode('ascii')}\n")
    print(f"Timestamp v{versione} firmato.")
    return 0


def comando_pubblica():
    dati = base64.b64decode(os.environ.get("TIMESTAMP_B64", ""), validate=True)
    if not dati:
        raise Fermo("non è arrivato nessun timestamp dal passo della firma")
    api = _api()
    adesso = dt.datetime.now(dt.timezone.utc)
    avvisi = []
    fatto = sostituisci(api, dati, avvisi)
    documento = json.loads(dati)["signed"]
    print(f"Timestamp v{documento['version']} pubblicato, scade il {documento['expires']}." if fatto else "Niente da pubblicare.")
    tieni_acceso(api, adesso, avvisi)
    for a in avvisi:
        print(f"::warning::{a}")
    guai = scadenze_vicine(api, adesso)
    for g in guai:
        print(f"::error::{g}")
    return 1 if guai else 0


def main(argv):
    comandi = {"firma": comando_firma, "pubblica": comando_pubblica}
    if len(argv) != 1 or argv[0] not in comandi:
        print("uso: rinnova_timestamp.py firma|pubblica", file=sys.stderr)
        return 64
    try:
        return comandi[argv[0]]()
    except Fermo as e:
        print(f"::error::{e}")
        return 1
    except Exception as e:
        # Mai il messaggio dell'eccezione: solo il tipo. Così nessun valore può finire nei log.
        print(f"::error::errore inatteso: {type(e).__name__}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
