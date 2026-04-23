# Ragnar Protect

Ragnar Protect is a Windows-focused defensive scanner and active monitoring tool.

Current MVP features:

- Signature and heuristic scanning for suspicious scripts and binaries
- External behavior rules loaded from `rules/behavior_rules.json`
- Optional YARA rule scanning from `rules/yara/*.yar`
- PE-focused YARA and packer heuristics for UPX-style executables
- AMSI integration when available on Windows
- Authenticode verification through PowerShell
- Local reputation scoring based on hash history, certificate, and publisher metadata
- Deep ZIP/TAR archive inspection
- Executable folder scan mode with JSON and Markdown reports
- Native local isolated execution for suspicious executables
- Quick scan mode for common user hotspots
- System audit for running processes, startup persistence, and scheduled tasks
- SQLite-backed detection, blocklist, and event history
- Quarantine, restore, and execution blocking for flagged files
- Real-time file monitoring
- Live process guard for high-risk script hosts
- Self-protection rules so Ragnar does not rescan or quarantine its own workspace, build outputs, helper, or app data
- GitHub updater with manifest comparison and staged `.exe` downloads
- Tkinter GUI with scan, monitoring, history, and blocklist tabs

## Quick start

```powershell
python -m pip install -r requirements.txt
python main.py
```

CLI scan:

```powershell
python main.py --scan C:\Users\Public\Downloads
```

Executable folder report:

```powershell
python main.py --scan-executables C:\Users\Public\Downloads
```

Prepare a local isolated execution bundle:

```powershell
python main.py --prepare-exe-sandbox C:\Users\Public\Downloads\suspicious.exe
```

Quick scan:

```powershell
python main.py --quick-scan
```

System audit:

```powershell
python main.py --system-audit
```

Short monitoring run:

```powershell
python main.py --monitor-seconds 30
```

Run background protection:

```powershell
python main.py --protect --nogui
```

Check the GitHub update manifest and stage a newer build when needed:

```powershell
python main.py --check-updates --nogui
python main.py --update-status --nogui
```

Check automatic error-report mail status:

```powershell
python main.py --error-report-status --nogui
```

Install a local Resend key file next to the built `.exe`:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_resend_key.ps1 -ApiKey re_xxxxx
```

Install startup protection with highest privileges:

```powershell
python main.py --install-startup --nogui
```

Remove the startup task:

```powershell
python main.py --remove-startup --nogui
```

Build a Windows `.exe` with PyInstaller:

```powershell
pyinstaller --clean RagnarProtect.spec
```

Generated binary:

```text
dist\RagnarProtect.exe
```

Generate an update manifest for the GitHub updater:

```powershell
python .\scripts\build_update_manifest.py --exe .\dist\RagnarProtect.exe --repo ragnar152743/ragnar-protect-MAJ --out .\manifest.json
```

## Notes

- This is a user-mode prototype, not a kernel antivirus.
- AMSI and Authenticode checks work only on Windows.
- Process blocking and process guard are stronger with `psutil` installed.
- YARA scanning is enabled when `yara-python` is installed successfully.
- The default update source is `ragnar152743/ragnar-protect-MAJ` on branch `main`.
- Automatic error-report emails require a Resend API key from `RAGNAR_RESEND_API_KEY` or a local key file such as `dist\RagnarProtect.resend_key.txt`; recipient and sender can be overridden with `RAGNAR_ERROR_REPORT_TO` and `RAGNAR_ERROR_REPORT_FROM`.
