"""
Admin-Tool: Erstellt ein Machine Token für einen Kiosk-Client manuell.

Sinnvoll für Recovery-Szenarien (Token verloren, kein Re-Deploy möglich).
Muss auf dem Proxy-Host laufen, weil es den SECRET_KEY und die DB braucht.

Aufruf:
    python generate_token.py --agent-id <TACTICAL_AGENT_ID> --hostname <HOSTNAME>
"""
import argparse
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))

import database  # noqa: E402
from auth import create_machine_token  # noqa: E402


async def _run(agent_id: str, hostname: str) -> str:
    await database.init_db()
    # Bewusst KEINE token_version-Bumpung – sonst bricht ein laufender Client
    # auf dem Gerät. Das Token erbt die aktuelle Version.
    return await create_machine_token(agent_id, hostname)


def main():
    parser = argparse.ArgumentParser(description="Machine Token Generator für Softshelf")
    parser.add_argument("--agent-id", required=True, help="Tactical RMM Agent ID")
    parser.add_argument("--hostname", required=True, help="Hostname des Geräts")
    args = parser.parse_args()

    token = asyncio.run(_run(args.agent_id, args.hostname))
    print(f"\nMachine Token für {args.hostname}:")
    print(f"\n  {token}\n")
    print("WICHTIG: Dieses Token nur dem zugehörigen Gerät geben.")
    print("Es erlaubt ausschließlich Zugriff auf den eigenen Agenten.\n")


if __name__ == "__main__":
    main()
