# Reporting events: native agent, this project's client, the real server's event table

Recorded 2026-10-06 (inventory 9.10, ledger C71 to C73). Nothing here is a raw capture: client ids, cookies, signed
URLs and addresses are removed; raw captures stay local and are never committed.

| File | Content |
| --- | --- |
| `native-install-events.json` | Decoded `ReportEventBatch` requests of a native Windows Update Agent 1507.2601.30012.0 (Windows 11 25H2, 10.0.26200) against the real lab WSUS: the install of the `.NET` cumulative update KB5126052 that needs a restart (`181`, then `201` with `Win32HResult` 2359301), and the failed install attempts of two Windows Installer test updates (`161`, `181`, `182` with `0x80246007`). Per event: namespace, id, source, sequence, `Win32HResult`, update, `AppName`, replacement strings, `MiscData` (the `U` and `V` lists of event `156` reduced to their sizes), the extended-data fields and whether an empty `PrivateData` was present. |
| `our-client-events.json` | The same decoding for the three posts of this project's client (an uninstall, an install, and a replay of the install job record with the title fetched). |
| `native-156-lists.json` | The client status event `156` (inventory 9.11, ledger C77 to C79): the `MiscData` keys of a native event, the `U` and `V` update-id lists of a native agent and of this project's client on the same machine, their comparison and the list sizes over time. Computer ids removed. |
| `susdb-client-event-table.csv` | `SUSDB.dbo.tbEvent` joined with `tbEventMessageTemplate` (language `en`) for namespace 1 of the real server: event id, state, severity, log level and the message template. WSUS static data. Namespace 1 sources: `101` Client Agent, `102` Automatic Update component, `103` Client Server Protocol Talker, `104` Inventory component, `105` Update handler, `106` CBS, `107` DPX. |

Read with `SELECT` only; the database was never edited.
