# Contributing to dnswatch

Thank you for contributing to `dnswatch`. This project adheres to disciplined network systems engineering, zero-dependency packet dissection, and reproducible testing.

---

## 1. Development Environment

### Prerequisites
- Python 3.10 or newer (tested on 3.12).
- Virtual environment (`venv`) to isolate dependencies.
- `ruff` for linting and code formatting.
- `pytest` for deterministic unit testing.

### Setup
```bash
git clone https://github.com/netequator/dnswatch.git
cd dnswatch
python -m venv .venv

# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install pytest ruff build
pip install -e .
```

---

## 2. Engineering Standards

### Zero "AI Smell" & Minimalist Code
- Do not include emojis anywhere: commit messages, PR descriptions, code comments, documentation, or CLI outputs.
- Keep abstractions narrow. Do not introduce generic factories, speculative interfaces, or heavy third-party dependencies.
- Use Python standard library primitives exclusively (`struct`, `socket`, `math`, `ipaddress`, `dataclasses`).

### Deterministic Testing
- Live capture sockets must remain strictly separated from binary parsing logic.
- All new protocol features or bug fixes must include deterministic unit tests in `tests/` using synthetic byte buffers or offline `.pcap` streams.
- Tests must execute without requiring root/administrator permissions or active network interfaces.

### Code Quality Checklist
Before submitting a pull request, verify:
```bash
ruff check .
pytest tests/ -v
```

---

## 3. Git & Pull Request Guidelines

### Commit Messages
- Use concise, lower-case technical descriptions explaining the specific change.
- Format: `<type>: <description>`
  - `feat: add rfc 1035 synthetic response builder`
  - `fix: correct pointer cursor lock on nested label`
  - `test: add deterministic test for qinq double vlan peeling`
  - `refactor: simplify in-memory blocklist hash lookup`
  - `docs: update wire protocol bitfield specifications`

### Scope Discipline
- Keep pull requests focused on a single GitHub Issue or feature.
- Avoid multi-issue mega-commits. Group changes into 1 to 3 logical commits.
- Ensure all tests pass and the repository tree remains clean.
