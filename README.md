# JS Fetch

**JS Fetch** is a lightweight Python-based JavaScript URL security scanner designed to quickly inspect JavaScript files for potentially exposed secrets, tokens, credentials, and endpoints.

It can process a list of JavaScript URLs or local JavaScript files, fetch their content, scan them using pattern-based detection, and save the findings to an output file.

## Features

* Scan remote JavaScript URLs
* Scan local JavaScript files
* Automatically skip non-JavaScript entries
* Detect potential API keys and secrets
* Detect bearer and authentication tokens
* Detect hardcoded passwords and usernames
* Extract email addresses
* Extract URLs and endpoints
* Remove duplicate findings
* Save results to a clean output file
* Automatically checks and installs the required Python dependency

## Requirements

* Python 3
* Internet connection when scanning remote JavaScript files

The tool automatically checks for the `requests` package when it starts and attempts to install it if it is missing.

## Installation

Clone the repository:

```bash
git clone https://github.com/Muzanespisito/javascript-scan.git
cd javascript-scan
```

No manual dependency installation is normally required.

You can also install the dependency manually:

```bash
pip3 install requests
```

## Usage

The tool requires two arguments:

* `-f` / `--file` — input file containing JavaScript URLs or paths
* `-o` / `--output` — file where the findings will be saved

Example:

```bash
python3 jsfetch.py -f urls.txt -o results.txt
```

## Input File

Create a file containing the JavaScript URLs you want to scan.

Example `urls.txt`:

```text
https://example.com/app.js
https://example.com/assets/main.js
https://example.com/static/config.js
```

Local JavaScript files can also be provided:

```text
./app.js
./config.js
./assets/main.js
```

The scanner checks whether each entry points to a `.js` file before processing it.

## What It Detects

JS Fetch uses pattern-based detection to look for several categories of potentially sensitive information.

### API Keys & Secrets

Examples include:

* AWS access keys
* OpenAI / secret keys
* Groq / Google AI keys
* Google API keys
* Slack tokens
* GitHub tokens
* GitHub OAuth tokens
* Google OAuth tokens
* JWT tokens
* API key assignments
* Secret assignments
* Long potential tokens

The detection patterns are defined directly in the scanner.

### Authentication Tokens

The scanner also looks for patterns such as:

```text
Bearer tokens
Token assignments
Auth tokens
```

### Credentials

It can flag potential:

```text
Email addresses
Hardcoded passwords
Username assignments
```

### URLs & Endpoints

HTTP and HTTPS URLs found inside JavaScript content are extracted and reported as potential endpoints.

## Output

Findings are displayed directly in the terminal and saved to the output file specified with `-o`.

Example:

```text
[API_KEY] AWS Access Key: AKIAxxxxxxxxxxxxxxxx (file: https://example.com/app.js)
[TOKEN] Bearer token: xxxxxxxxxxxxxxxxxxxx (file: https://example.com/app.js)
[CRED] Email (potential username): test@example.com (file: https://example.com/app.js)
[URL] Endpoint: https://api.example.com/v1/users (file: https://example.com/app.js)
```

If no findings are detected in a JavaScript file, the tool reports:

```text
[OK] No secrets found
```

## How It Works

The scanning process is straightforward:

```text
Input file
    ↓
Check JavaScript entries
    ↓
Fetch JavaScript content
    ↓
Scan for sensitive patterns
    ↓
Remove duplicate findings
    ↓
Display results
    ↓
Save results to output file
```

For remote files, the tool performs an HTTP GET request and reads the returned content. Local files are read directly from the filesystem.

## Example

```bash
python3 jsfetch.py -f urls.txt -o findings.txt
```

After the scan finishes:

```text
Results saved to: findings.txt
```

## Legal & Responsible Use

This tool is intended for authorized security testing, research, bug bounty programs, and security assessments.

Only scan JavaScript resources that you own or have explicit permission to test.

Finding a token, credential, or endpoint does not necessarily mean it is valid, active, or vulnerable. Always verify findings responsibly and avoid accessing data or systems without authorization.

## Author

**MuZaN**

GitHub: https://github.com/Muzanespisito

## Disclaimer

JS Fetch is provided for security research and educational purposes. The author is not responsible for misuse of the tool or for actions performed against systems without proper authorization.

---

### Coded with vibe coding.
