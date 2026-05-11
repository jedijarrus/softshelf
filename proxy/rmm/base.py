"""RMM-Backend-Interface.

Definiert die minimale API die Softshelf von einem RMM-Tool erwartet.
Python-Protocol — duck-typing reicht, keine zwingende Vererbung. Dient
primaer als Doku + Type-Hint und beschreibt was ein neuer Adapter
implementieren muss.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class RMMClient(Protocol):
    """Schnittstelle die Softshelf von einem RMM-Backend nutzt.

    Alle Methoden sind async. Implementationen muessen httpx (oder
    aequivalent) intern verwalten — kein Connection-Sharing erwartet.

    Identitaet:
      Agent-IDs sind opak fuer Softshelf — werden 1:1 vom RMM uebernommen
      und in `agents.agent_id` persistiert. Beim Backend-Wechsel mit
      anderen ID-Formaten muss eine Migration die alten IDs auf neue
      mappen (z.B. via hostname-Lookup).
    """

    async def run_command(
        self,
        agent_id: str,
        ps_code: str,
        *,
        run_as_user: bool = False,
        timeout: int = 60,
    ) -> str:
        """Fuehrt PowerShell-Code auf dem Agent aus.

        - Default: SYSTEM-Context.
        - `run_as_user=True`: in der aktiven User-Session ausfuehren
          (wichtig fuer msstore-Installs).
        - Returnt stdout (text). Softshelf erwartet KEIN Output-Capture-
          Garantie — wir nutzen fire-and-forget Bootstrap, Resultat kommt
          via Agent-Callback an `/api/v1/callback/{job_id}` zurueck.
        - `timeout` ist die Delivery-Timeout (RMM → Agent), nicht die
          Ausfuehrungszeit auf dem Agent.

        Raises bei Delivery-Fehler (Agent offline, RMM unerreichbar).
        """

    async def run_script_by_name(
        self, agent_id: str, script_name: str, timeout: int = 600,
    ) -> dict:
        """Fuehrt ein im RMM-Script-Library hinterlegtes Skript aus.

        Aktuell nur fuer Force-Reinstall des Kiosk-Clients genutzt
        ("Kiosk Install"-Script). Wenn das neue RMM kein vergleichbares
        Konzept hat, kann das ueber run_command emuliert werden.

        Returnt {"ok": bool, "stdout": str, "exit_code": int}.
        """

    async def get_installed_software(self, agent_id: str) -> list[dict]:
        """Liest die Software-Inventur des Agents.

        Pro Eintrag mindestens: `name` (display-name), optional `version`.
        Wird vom winget-Enrichment und der custom-Paket-Detection genutzt.

        Wenn das neue RMM keine native Software-Inventur hat, muss diese
        Methode ueber einen run_command + parsing der Registry oder
        Get-Package emuliert werden.
        """

    async def get_agent(self, agent_id: str) -> dict | None:
        """Basic-Info zum Agent: mindestens `hostname`. None wenn unbekannt."""

    async def find_agent_by_hostname(self, hostname: str) -> dict | None:
        """Reverse-Lookup hostname → agent_id (Setup-Register-Flow)."""

    async def find_agent_by_ip(self, ip: str) -> dict | None:
        """Reverse-Lookup IP → agent_id (Setup-Register-Flow)."""

    async def check_agent_status(self, agent_id: str) -> dict:
        """Liefert online/last_seen-Info fuer Pre-Flight-Checks vor Dispatch.

        Returnt mindestens {"online": bool, "last_seen": iso8601 | None}.
        """
