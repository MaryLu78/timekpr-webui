import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')

host = '0.0.0.0'
port = 5000

try:
    with open(CONFIG_PATH, 'r', encoding='utf-8') as config_file:
        config = json.load(config_file)
        host = config.get('host', host)
        port = int(config.get('port', port))
except Exception:
    pass

workers = os.environ.get('GUNICORN_WORKERS', '2')
timeout = os.environ.get('GUNICORN_TIMEOUT', '120')

gunicorn_executable = os.path.join(BASE_DIR, '.venv', 'bin', 'gunicorn')
bind = f'{host}:{port}'

os.execv(
    gunicorn_executable,
    [
        gunicorn_executable,
        '--workers', workers,
        '--bind', bind,
        '--timeout', timeout,
        'app:app',
    ],
)
