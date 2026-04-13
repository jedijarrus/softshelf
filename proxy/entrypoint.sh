#!/bin/sh
# Sorgt für korrekte Permissions auf dem Datenvolume und droppt dann
# auf den unprivilegierten 'softshelf' User. Existierende Deployments mit
# root-owned data/ werden beim ersten Start automatisch umgechownt.
set -e

mkdir -p /app/data
chown -R softshelf:softshelf /app/data

exec gosu softshelf "$@"
