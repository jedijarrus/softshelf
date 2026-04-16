"""
GET /api/v1/packages
Gibt die vom Admin freigeschalteten Pakete zurück, angereichert mit dem
aktuellen Installationsstatus + Metadaten (Version, Publisher) des
anfragenden Geräts. Bei custom-Paketen wird zusätzlich aus dem
agent_installations-Tracking die installierte Version mit der current
Version verglichen → update_available-Flag für die Kiosk-UI.

Winget-Pakete werden aus dem agent_winget_state geledigt — der Status
kommt vom letzten nightly oder targeted Re-Scan, kein Tactical-Round-Trip
mehr nötig pro /packages-Aufruf.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import database
import winget_catalog
from auth import verify_machine_token
from tactical_client import TacticalClient

router = APIRouter()


class Package(BaseModel):
    name: str
    display_name: str
    category: str = "Allgemein"
    type: str = "choco"
    version: str | None = None
    publisher: str | None = None
    installed: bool = False
    # Versionierung (nur custom)
    installed_version_label: str | None = None
    current_version_label: str | None = None
    update_available: bool = False


@router.get("/packages", response_model=list[Package])
async def list_packages(token: dict = Depends(verify_machine_token)):
    agent_id = token["agent_id"]
    pkg_rows = await database.get_packages()

    # Staged-Rollout Gate: fuer Pakete mit staged_rollout=1 zeigen wir
    # update_available nur dann, wenn es einen aktiven Rollout gibt UND
    # dessen current_phase den Ring dieses Agents erreicht hat.
    # Ring 1 = erste Phase, Ring 3 = letzte (Produktion).
    agent = await database.get_agent(agent_id)
    agent_ring = (agent or {}).get("ring") or 3
    active_rollouts = await database.get_active_rollout_phases()

    if not pkg_rows:
        raise HTTPException(status_code=503, detail="Keine Pakete freigegeben. Admin-Oberfläche öffnen.")

    # Tactical-Software-Scan brauchen wir nur wenn es choco-/custom-Pakete gibt.
    # Für reine winget-Setups sparen wir den Round-Trip.
    needs_tactical = any(
        (row.get("type") or "choco") in ("choco", "custom") for row in pkg_rows
    )
    installed_meta: dict[str, tuple[str, str]] = {}
    if needs_tactical:
        try:
            installed_list = await TacticalClient().get_installed_software(agent_id)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Tactical RMM nicht erreichbar: {e}")
        installed_meta = {
            item.get("name", "").lower(): (item.get("version", ""), item.get("publisher", ""))
            for item in installed_list
        }

    def _find(needle: str) -> tuple[bool, str | None, str | None]:
        """Substring-Match in beide Richtungen, mit Metadaten-Rückgabe."""
        nl = (needle or "").lower().strip()
        if not nl:
            return False, None, None
        for installed_name, (version, publisher) in installed_meta.items():
            if nl in installed_name or installed_name in nl:
                return True, version or None, publisher or None
        return False, None, None

    # Tracking-Daten dieses Agents pro Paketname (custom)
    tracked = await database.get_agent_installations(agent_id)
    tracked_by_pkg = {t["package_name"]: t for t in tracked}

    # Winget-State + Choco-State dieses Agents
    winget_state = await database.get_agent_winget_state(agent_id)
    choco_state = await database.get_agent_choco_state(agent_id)

    result = []
    for row in pkg_rows:
        ptype = row.get("type") or "choco"

        if ptype == "winget":
            # Status primaer aus agent_winget_state. Fallback: agent_installations
            # — wenn winget heuristisch via ARP installiert hat aber `winget list`
            # / `winget export` das Paket nicht zeigt (z.B. 1Password installiert
            # via Hersteller-EXE, winget findet's nur per DisplayName-Match).
            wid = row["name"]
            state = winget_state.get(wid)
            os_managed = winget_catalog.is_os_managed(wid)
            if state:
                installed_version = state.get("installed_version") or ""
                available_version = state.get("available_version")
                # OS-managed Pakete (Edge, OneDrive, Office, Teams, …) lassen
                # sich NICHT via winget upgraden. Wir maskieren das
                # Update-Flag damit der Kiosk-Client gar nicht erst den
                # Updaten-Button anbietet — sonst landet der User in einem
                # „install technology is different"-Failure.
                if os_managed:
                    available_version = None
                is_installed = True
                version = installed_version or None
                publisher = row.get("winget_publisher") or None
                installed_label = installed_version or None
                current_label = available_version or None
                update_avail = bool(available_version)
            elif tracked_by_pkg.get(wid):
                # Heuristisch installiert via Softshelf — Kiosk soll's als
                # installiert anzeigen, ohne Versions-Info.
                is_installed = True
                version = None
                publisher = row.get("winget_publisher") or None
                installed_label = None
                current_label = None
                update_avail = False
            else:
                is_installed = False
                version = None
                publisher = row.get("winget_publisher") or None
                installed_label = None
                current_label = None
                update_avail = False

            result.append(Package(
                name=wid,
                display_name=row["display_name"],
                category=row.get("category", "Allgemein"),
                type="winget",
                version=version,
                publisher=publisher,
                installed=is_installed,
                installed_version_label=installed_label,
                current_version_label=current_label,
                update_available=update_avail,
            ))
            continue

        if ptype == "custom":
            needle = row.get("detection_name") or row.get("display_name") or row["name"]
        else:
            needle = row["name"]

        is_installed, version, publisher = _find(needle)

        installed_label = None
        current_label = None
        update_avail = False

        # Choco-Pakete: agent_choco_state ist die deterministische Quelle für
        # installed_version + available_version. Wenn vorhanden, überschreibt
        # sie die Substring-Heuristik vom Tactical-Scan.
        if ptype == "choco":
            cstate = choco_state.get(row["name"])
            if cstate:
                cs_installed = cstate.get("installed_version")
                cs_avail = cstate.get("available_version")
                if cs_installed:
                    is_installed = True
                    version = cs_installed
                    installed_label = cs_installed
                if cs_avail:
                    current_label = cs_avail
                    update_avail = True

        if ptype == "custom":
            # Current-Version-Label aus package_versions ziehen
            cv_id = row.get("current_version_id")
            if cv_id:
                cv = await database.get_package_version(cv_id)
                if cv:
                    current_label = cv.get("version_label")
            # Tracking dieses Agents (falls vorhanden)
            t = tracked_by_pkg.get(row["name"])
            if t:
                installed_label = t.get("version_label")
                update_avail = bool(t.get("outdated"))
                # Wenn der Tracking-Eintrag existiert und Tactical es noch nicht
                # gescannt hat, werten wir es trotzdem als 'installed'
                if not is_installed:
                    is_installed = True

        result.append(Package(
            name=row["name"],
            display_name=row["display_name"],
            category=row.get("category", "Allgemein"),
            type=ptype,
            version=version,
            publisher=publisher,
            installed=is_installed,
            installed_version_label=installed_label,
            current_version_label=current_label,
            update_available=update_avail,
        ))

    # Staged-Rollout Update-Gate: fuer staged Pakete wird update_available
    # nur sichtbar gemacht wenn der Rollout den Agent-Ring erreicht hat.
    # Rollout in Phase N → alle Agents in Ring <= N kriegen das Update.
    # Kein Rollout aktiv → staged Paket zeigt kein Update (Admin muss erst
    # Rollout starten).
    staged_map = {p["name"]: bool(p.get("staged_rollout")) for p in pkg_rows}
    for p in result:
        if not staged_map.get(p.name):
            continue
        if not p.update_available:
            continue
        phase = active_rollouts.get(p.name)
        if phase is None or phase < agent_ring:
            # Kein aktiver Rollout ODER Rollout hat Ring dieses Agents noch nicht erreicht
            p.update_available = False
            p.current_version_label = None  # Version-Info verstecken damit UI nicht verwirrt

    # "Hidden in Kiosk"-Filter: Pakete mit packages.hidden_in_kiosk=1 werden
    # nur ausgeliefert wenn sie auf DIESEM Agent installiert sind.
    # Use-case: Admin-only Remote-Deploy-Software — User sieht sie nicht im
    # Kiosk-Grid, aber sobald installiert kann er sie sehen/updaten/removen.
    hidden_map = {p["name"]: bool(p.get("hidden_in_kiosk")) for p in pkg_rows}
    def _keep(p: Package) -> bool:
        if not hidden_map.get(p.name):
            return True
        return p.installed
    return [p for p in result if _keep(p)]
