# Database backup and recovery

Create a consistent snapshot while the API is running:

```powershell
.\.venv\Scripts\python.exe -m aegisweave backup --db var/aegisweave.db --output var/backups/my-snapshot
```

The output directory must be new. The command uses SQLite's online backup API, so committed WAL data is included without copying a potentially inconsistent live database file. It checks database integrity and publishes a manifest with the schema version and SHA-256 checksum. A folder without a manifest is incomplete.

Restore to a new, unused file:

```powershell
.\.venv\Scripts\python.exe -m aegisweave restore --backup var/backups/my-snapshot --output var/recovery/restored.db
```

Existing database files are never overwritten by this command. Restore verifies the checksum and SQLite integrity. Inspect the restored data, stop the API in a planned maintenance window, then start it with `serve --db var/recovery/restored.db` if switching is intended. This command does not switch the running service.

Snapshots contain sensitive network evidence. Protect the backup directory and copy completed snapshots to appropriately protected independent storage. A checksum detects corruption; it does not authenticate a backup against an attacker who can replace both the database and manifest.

The model artifacts, detection configuration, role credentials, and collector spool are separate recovery items. Preserve the verified model directory and configuration version alongside a deployment record. Keep credentials in the deployment's secret storage. Stop the collector before moving or restoring its spool; replaying an older spool can redeliver records. Do not replace a running collector's SQLite files.

A backup does not recover records already removed by retention. Confirm retention capacity, backup frequency, recovery-point and recovery-time requirements during site sizing. The default application event count cap is 100,000; it is not a guarantee of 30 days of complete traffic history.

Validation on 16 September: online WAL snapshot unit test, corruption rejection, overwrite refusal, and backup/restore of the existing dashboard database to a separate verification file all passed. Full host disaster recovery and off-host backup scheduling remain deployment work.
