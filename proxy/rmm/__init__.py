"""RMM-Backend-Abstraktion.

Softshelf nutzt ein RMM-Tool (Remote Monitoring & Management) um Befehle
auf Agents auszufuehren — aktuell Tactical RMM. Diese Schicht entkoppelt
den Rest des Codes vom konkreten Backend, damit ein Wechsel (z.B. zu
NinjaOne, Atera, Intune) ohne Edit aller Call-Sites moeglich ist.

Verwendung:

    from rmm import get_rmm_client
    tc = get_rmm_client()
    await tc.run_command(agent_id, ps_code)

Hinzufuegen eines neuen Backends:

  1. Implementierung in `proxy/rmm/<name>.py` schreiben. Muss die Methoden
     aus `RMMClient` (siehe `base.py`) bereitstellen — Python Duck-Typing,
     keine zwingende Vererbung noetig.
  2. In `get_rmm_client()` einen neuen Branch fuer settings.rmm_backend=='<name>'
     ergaenzen.
  3. Settings-Keys fuer URL/API-Key/etc analog zu tactical_url/tactical_api_key
     in `config.py` registrieren.
  4. Migration: wenn das neue RMM andere Agent-IDs nutzt, separate Spalte
     `agents.rmm_agent_id` einfuehren und Mapping pflegen.

Siehe ARCHITEKTUR.md "RMM-Backend austauschen" fuer vollstaendige Anleitung.
"""

from rmm.base import RMMClient
from tactical_client import TacticalClient, get_queue_status

__all__ = ["RMMClient", "get_rmm_client", "get_queue_status"]


def get_rmm_client() -> RMMClient:
    """Factory: liefert die aktuelle RMM-Backend-Instanz.

    Aktuell hart auf TacticalClient. Beim Hinzufuegen weiterer Backends
    hier auf settings.rmm_backend dispatchen — beispielsweise:

        from config import settings  # synchrone bootstrap-settings
        backend = (settings.rmm_backend or "tactical").lower()
        if backend == "tactical":
            return TacticalClient()
        if backend == "ninjaone":
            from rmm.ninjaone import NinjaOneClient
            return NinjaOneClient()
        raise ValueError(f"Unbekanntes RMM-Backend: {backend}")
    """
    return TacticalClient()
