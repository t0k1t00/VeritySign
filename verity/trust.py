"""Local trust store: pinned public-key fingerprints (never private keys)."""
import json
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "trusted_keys.json"


def _load(path):
    p = Path(path or DEFAULT_PATH)
    try:
        data = json.loads(p.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save(data, path):
    Path(path or DEFAULT_PATH).write_text(json.dumps(data, indent=2), "utf-8")


def lookup(fp, path=None):
    return _load(path).get(fp)


def pin(fp, label, path=None):
    data = _load(path)
    data[fp] = label.strip() or "unnamed"
    _save(data, path)


def unpin(fp, path=None):
    data = _load(path)
    data.pop(fp, None)
    _save(data, path)


def all_keys(path=None):
    return _load(path)
