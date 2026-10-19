# Hatfind

```text
  _   _       _    __ _
 | | | | __ _| |_ / _(_)_ __   __| |
 | |_| |/ _` | __| |_| | '_ \ / _` |
 |  _  | (_| | |_|  _| | | | | (_| |
 |_| |_|\__,_|\__|_| |_|_| |_|\__,_|
```

**Authorized reconnaissance and access-control triage**

Hatfind is a low-noise subdomain and endpoint reconnaissance tool for bug-bounty work and authorized IDOR/access-control review.

This project helps you answer:

1. Which in-scope subdomains are known?
2. Which of them respond over HTTP(S)?
3. Which URLs and API-looking endpoints can be found passively or by a controlled crawl?
4. Which URLs contain object identifiers that deserve manual access-control review?

It does **not** automatically prove IDOR, bypass authentication, mutate data, replay requests as another user, or claim a vulnerability. The output is a prioritized list of investigation leads for systems you are authorized to test.

## What happens during a scan

The default `bugbounty` profile follows this process:

```text
Target domain and optional scope file
        |
        v
Scope validation and tool preflight
        |
        v
Passive subdomain discovery
  - subfinder
  - crt.sh certificate data
        |
        v
Scope filtering (allow list, then deny list)
        |
        v
Live-host and metadata collection
  - httpx status, title, technology, server and IP data
        |
        v
URL collection per live host
  - Katana controlled crawl (optional)
  - gau historical URLs (optional)
        |
        v
URL normalization and endpoint inventory
        |
        v
IDOR/access-control candidate triage
  - numeric path identifiers
  - UUID path identifiers
  - ID-like query parameters
  - API and resource path signals
        |
        v
Run directory with JSON, text and error reports
```

The `bugbounty` profile is intentionally lower-noise. Nmap is never run unless `--nmap` is explicitly supplied.

## Features

- Scope-aware subdomain discovery using `subfinder` and `crt.sh`
- Optional JSON allow and deny lists; deny rules always win
- Live-host metadata through ProjectDiscovery `httpx`
- Controlled active crawling with `katana`
- Historical URL discovery with `gau`
- URL normalization and duplicate removal
- API/resource path and object-identifier detection
- Confidence-scored `idor_candidates.json`
- Run-specific output directories so previous results are not overwritten
- Tool preflight with required versus optional dependency reporting
- Rate, timeout, worker, crawl-depth and host-count controls
- Optional lower-noise Nmap service detection
- Standard-library Python code and unit tests

## Authorization and safety

Use this tool only against assets that you own or that a security program explicitly allows you to test. Before every run, confirm the program's current scope, request limits, authentication rules, and prohibited actions.

The scanner is observation-only from the application's perspective. It does not:

- Change request bodies
- Send arbitrary ID substitutions
- Replay requests under a second identity
- Create, edit or delete application data
- Attempt authentication bypasses
- Treat an identifier in a URL as proof of IDOR

An IDOR candidate means only: “this URL has an object-like identifier and is worth reviewing with an authorized workflow.”

## Requirements

- Python 3.10 or newer
- `subfinder` and `httpx` on `PATH` for a normal scan
- `katana` and `gau` are optional; unavailable optional tools are reported and skipped
- Nmap is optional and only needed when `--nmap` is explicitly selected

The Python code uses only the standard library. `requirements.txt` is intentionally empty of third-party packages.

### Windows setup

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

Install the external tools separately and make sure their installation directory is on `PATH`:

```powershell
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

Install Nmap from <https://nmap.org/download.html> only when the program permits service detection.

Check that tools are visible before scanning:

```powershell
where.exe subfinder
where.exe httpx
where.exe katana
where.exe gau
where.exe nmap
```

`subfinder` and `httpx` are required. `katana`, `gau` and `nmap` are optional depending on the selected options.

### Linux setup

On Debian or Ubuntu, install Python, virtual-environment support, Go and the optional Nmap package:

```bash
sudo apt update
sudo apt install -y python3 python3-venv golang-go nmap
```

Create the virtual environment and install the Python requirements:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Install the Go-based reconnaissance tools:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

Add the Go binary directory to the current shell's `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

To keep that setting for future Bash sessions:

```bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc
```

Verify the tools:

```bash
command -v subfinder
command -v httpx
command -v katana
command -v gau
nmap --version
```

On Fedora, replace the Debian package command with:

```bash
sudo dnf install -y python3 python3-pip golang nmap
```

On Arch Linux, use:

```bash
sudo pacman -S --needed python go nmap
```

## Quick start

Run the default low-noise bug-bounty workflow:

```bash
python3 main.py example.com
```

On Windows, use:

```powershell
python main.py example.com
```

The domain may also be entered interactively:

```bash
python3 main.py
```

On Windows, use:

```powershell
python main.py
```

Use an explicit run location:

```powershell
python main.py example.com --run-dir runs\example-manual-review
```

By default, results are written to a new UTC directory under `runs`, for example:

```text
runs/run-20261015T120000Z/
```

## Scope control

Create a JSON file supplied by the bounty program or by your own authorization record. A bare hostname allows that hostname and its subdomains. A wildcard such as `*.example.com` allows subdomains but not the bare root itself. `deny` is evaluated first and always wins.

Example `scope.json`:

```json
{
  "allow": [
    "example.com",
    "*.api.example.com",
    "portal.example.com"
  ],
  "deny": [
    "admin.example.com",
    "staging.example.com"
  ]
}
```

Run with the scope file:

```powershell
python main.py example.com --scope-file scope.json
```

When no scope file is supplied, the root domain and its subdomains are allowed. That default is convenient, but a program-specific allow/deny file is safer.

## Useful options

```text
--profile bugbounty       Low-noise defaults; this is the default
--profile thorough        More workers, rate and crawl depth
--scope-file FILE         JSON allow/deny hostname rules
--output-dir DIRECTORY    Parent directory for a generated run directory
--run-dir DIRECTORY       Use an exact output directory
--workers N               Parallel live-host workers
--rate-limit N            Approximate tool request rate
--timeout SECONDS         Tool and request timeout
--crawl-depth N           Katana crawl depth
--max-hosts N             Maximum live hosts to crawl
--no-crtsh                Skip crt.sh
--no-katana               Skip active Katana crawling
--no-gau                  Skip historical gau URLs
--nmap                    Explicitly enable lower-noise Nmap service checks
--nmap-top-ports N        Nmap top-port count when --nmap is used
```

Examples:

```powershell
# Lowest-noise pass: passive discovery and live-host inventory only
python main.py example.com --no-katana --no-gau

# Bug-bounty pass with stricter limits
python main.py example.com --workers 2 --rate-limit 2 --timeout 15

# Explicitly authorized service inventory; use only if allowed by the program
python main.py example.com --nmap --nmap-top-ports 100 --workers 2

# More complete URL collection, still without vulnerability testing
python main.py example.com --profile thorough --max-hosts 50
```

## Output files

Each run contains:

```text
run-.../
├── manifest.json
├── subdomains.txt
├── alive.txt
├── results.json
├── idor_candidates.json
└── summary.txt
```

### `subdomains.txt`

The merged, normalized, in-scope names returned by `subfinder` and `crt.sh`.

### `manifest.json`

Small reproducibility record containing the profile, UTC timestamps, scope rules, tool availability, scan controls and output counts.

### `alive.txt`

The in-scope hosts that `httpx` reported as responsive. The `--max-hosts` limit applies to the hosts sent to crawling and optional Nmap.

### `results.json`

The complete run record, including:

- Target domain and profile
- Scope rules and preflight information
- Scan controls
- Host status, title, technologies, headers and IP address
- Collected URLs and normalized endpoints
- Query parameter names
- JavaScript URL list
- Optional Nmap output
- Per-host and overall errors

### `idor_candidates.json`

Prioritized URL-only triage leads. Each candidate can include:

- Normalized URL and endpoint
- Redacted query values for sensitive names such as tokens or cookies
- Identifier location (`path` or `query`)
- Identifier type (`numeric`, `uuid`, or `id-like-name`)
- API/resource path signals
- Confidence score and confidence label
- A reminder that manual authorized verification is required

Scores prioritize review order; they are not probability estimates and are not vulnerability findings.

### `summary.txt`

A short human-readable run summary with host counts, URL counts, candidate counts and recorded errors.

## How to review IDOR/access-control candidates

Use the candidate report to choose a small number of high-value endpoints, such as account, order, invoice, file, project or user APIs.

For each candidate, follow the target program's authorized testing process:

1. Capture a request made by an authorized test account.
2. Identify the object identifier and the intended owner of that object.
3. Use a second authorized test account only if the program permits it.
4. Compare the same operation while changing only the object reference.
5. Check both the status code and whether the response contains data belonging to the other account.
6. Do not modify or delete data; use read-only objects and test records where possible.
7. Save the original request, comparison request, responses, timestamps and scope evidence for a report.

The tool does not perform these steps automatically because authorization context, HTTP methods, request bodies, CSRF protections and business rules cannot be inferred safely from a URL list.

## Testing the project

Run the unit tests:

```powershell
python -m unittest discover -s tests -v
```

Run syntax validation:

```powershell
python -m py_compile main.py tests\test_main.py
```

Inspect the CLI without starting a scan:

```powershell
python main.py --help
```

The tests cover domain and scope matching, deny precedence, scope-file parsing, URL normalization, endpoint extraction and candidate detection.

## Limitations

- Historical certificate and URL data may be stale.
- Authenticated endpoints are not discovered unless they appear in supplied tool output.
- JavaScript route strings, request bodies and GraphQL variables are not automatically parsed.
- A URL identifier can be a false positive and does not establish broken access control.
- The default crawl is limited by host count, worker count, rate and timeout settings.
- Missing optional tools reduce coverage but do not make the scan complete.
- Nmap is a separate, explicitly enabled activity and is not necessary for most IDOR triage.

## Disclaimer

Use this project only for systems you own or are explicitly authorized to assess. Follow the program's scope, rate limits, privacy requirements and prohibited-action rules. The author is not responsible for unauthorized use or damage.
