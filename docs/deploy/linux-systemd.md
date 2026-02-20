# Linux Deploy con systemd

Questa guida installa TimeKpr WebUI su Linux (Ubuntu/Debian) ed esegue l'app come servizio di sistema.

## 1) Prerequisiti

- Python 3.9+
- `git`
- `openssh-client`
- Accesso `sudo`

Comandi:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git openssh-client
```

## 2) Utente di servizio

```bash
sudo useradd --system --create-home --home-dir /opt/timekpr-webui --shell /usr/sbin/nologin timekpr-webui
```

## 3) Deploy codice

```bash
sudo mkdir -p /opt/timekpr-webui
sudo chown -R $USER:$USER /opt/timekpr-webui
git clone <URL_REPO> /opt/timekpr-webui
cd /opt/timekpr-webui
```

## 4) Virtualenv e dipendenze

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 5) Configurazione app e SSH key

1. Modifica `config.json` (porta/host/admin_username).
2. Crea o copia la chiave SSH in `ssh/timekpr_ui_key`.
3. Proteggi i permessi:

```bash
mkdir -p ssh
chmod 700 ssh
chmod 600 ssh/timekpr_ui_key
```

4. Assicura ownership dell'utente di servizio:

```bash
sudo chown -R timekpr-webui:timekpr-webui /opt/timekpr-webui
```

## 6) Database e prima inizializzazione

Avvio manuale una volta (opzionale ma consigliato):

```bash
sudo -u timekpr-webui /opt/timekpr-webui/.venv/bin/python /opt/timekpr-webui/app.py
```

Poi interrompi (`Ctrl+C`).

## 7) Installa il servizio systemd

```bash
sudo cp /opt/timekpr-webui/deploy/systemd/timekpr-webui.service /etc/systemd/system/timekpr-webui.service
sudo systemctl daemon-reload
sudo systemctl enable --now timekpr-webui
```

Nota: il servizio usa `run_gunicorn.py`, quindi `host` e `port` sono letti direttamente da `config.json`.

## 8) Verifica stato e log

```bash
sudo systemctl status timekpr-webui
sudo journalctl -u timekpr-webui -f
```

## 9) Comandi utili

```bash
sudo systemctl restart timekpr-webui
sudo systemctl stop timekpr-webui
sudo systemctl start timekpr-webui
```

## 10) Update applicazione

```bash
cd /opt/timekpr-webui
git pull
source .venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart timekpr-webui
```

## Note

- Il DB SQLite viene creato in `instance/timekpr.db`.
- La unità systemd consente scrittura solo in `instance/` (`ReadWritePaths`).
- Se usi reverse proxy (Nginx), imposta `"host": "127.0.0.1"` in `config.json`.
