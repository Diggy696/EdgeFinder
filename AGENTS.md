# PROJECT PURPOSE

- EdgeFinder researches sports matchups independently of sportsbook pricing.
- NFL first; future NBA, NCAAF, NCAAB, and Premier League support.
- Research only. Never automatically place wagers.

# ARCHITECTURE

- Python application with provider-independent data adapters.
- nflverse is the initial NFL statistical source.
- SQLite is the initial local storage.
- DraftKings odds will come from a separate future adapter.
- Keep sports-specific assumptions isolated from shared infrastructure.
- Preserve source identity, historical timestamps, and data provenance in future designs.
- Do not create probability estimates without defensible statistical methodology.

# DEVELOPMENT RULES

- Work in small, explicitly approved steps.
- Do not implement features beyond the current request.
- Ask for approval before significant architecture changes.
- Do not install packages or access paid APIs without approval.
- Do not execute Git commits, pushes, or repository modifications unless explicitly authorized.
- Do not access, print, expose, or commit credentials.
- Never commit .env files, local databases, or virtual environments.
- Explain changes and provide test results after development.
- Do not silently fix unrelated issues.
- Prefer reliable and testable implementations over fast development.

# ENVIRONMENT

- Windows, VS Code, PowerShell, Python 3.14.
- Python executable: .venv/Scripts/python.exe
- PowerShell activation may be restricted. Use the executable directly.
