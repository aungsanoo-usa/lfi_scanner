
# LFI Vulnerability Scanner

A powerful and multithreaded **Local File Inclusion (LFI)** scanner designed to detect vulnerabilities in web applications. This tool tests target URLs using user-provided payloads and identifies vulnerable endpoints.

---

## Features

- **User-Agent Rotation**: Mimics browser behavior by sending requests with random User-Agent headers.
- **Multithreading**: Scans multiple payloads concurrently for improved performance.
- **Payload Encoding**: Ensures payloads are safely URL-encoded.
- **Success Criteria Matching**: Detects vulnerabilities by looking for specific patterns in the response body.
- **Comprehensive Results**: Saves all vulnerable URLs to an output file for easy reference.

---

## Installation

### Prerequisites

- **Python 3.7+**
- Install required libraries using `pip`:

```bash
pip install -r requirements.txt
```

### Required Libraries

The tool uses the following libraries:

- `requests`
- `colorama`
- `urllib3`

---

## Usage

Run the script from the command line with the following options:

```bash
python lfi_scan.py -l urls.txt -p payloads.txt -t 5 -o vul_output.txt
```

### Command-Line Arguments

| Option          | Description                                       | Required |
|------------------|---------------------------------------------------|----------|
| `-l`, `--list`  | Path to a file containing the target URLs.         | Yes      |
| `-p`, `--payloads` | Path to a file containing the LFI payloads.       | Yes      |
| `-t`, `--threads` | Number of concurrent threads (default: 5).         | No       |
| `-o`, `--output`  | Path to the file where results will be saved.      | Yes      |

---

## Input File Examples

### URLs File (`urls.txt`)

```
http://example.com/vulnerable?file=
http://test.com/include=
http://site.com/index.php?page=
```

### Payloads File (`lfi.txt`)

```
../../../../etc/passwd
../../../../etc/shadow
../../../../boot.ini
..%2f..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts
```

---

## Example Output

### Console Output

```
┌────────────────────────────────────────┐
│       → Scanning URL: http://test.com/ │
└────────────────────────────────────────┘

[→] Scanning with payload: ../../../../etc/passwd
[✓] Vulnerable: http://test.com/include=../../../../etc/passwd - Response Time: 0.23s
[→] Scanning with payload: ../../../../etc/shadow
[✗] Not Vulnerable: http://test.com/include=../../../../etc/shadow - Response Time: 0.18s
```

### Output File (`output.txt`)

```
Vulnerable URLs:
http://test.com/include=../../../../etc/passwd
```

---

## How It Works

1. **URL Testing**:
   - Each URL is scanned with all the payloads from the payload file.

2. **Payload Encoding**:
   - Payloads are URL-encoded to ensure they are safely sent over HTTP.

3. **Response Analysis**:
   - The tool checks if the response body contains predefined success criteria, such as:
     - `root:`
     - `/etc/passwd`
     - `boot`

4. **Multithreading**:
   - Payloads are tested concurrently using the `ThreadPoolExecutor` for faster results.

5. **Results Saving**:
   - Vulnerable URLs are saved to the specified output file.

---

## Customization

### Modify Success Criteria

Edit the success criteria in the script to match your specific needs. Look for the following section:

```python
success_criteria = ["root:", "/etc/passwd", "boot"]
```

Add or modify patterns as needed.

---

## Disclaimer

This tool is intended for **educational purposes** and **authorized security testing** only. Unauthorized use of this tool to target systems without prior consent is illegal and unethical. The developers assume no responsibility for misuse or damages caused by this tool.

---

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve this project.

---

## Author

Created by [Aung San Oo](https://aungsanoo.com).

---

### Example Repository Structure

```
lfi-scanner/
├── lfi.py
├── urls.txt
├── lfi.txt
├── output.txt
├── README.md
└── requirements.txt
```

---

## Requirements File (`requirements.txt`)

```plaintext
requests
colorama
urllib3
```
