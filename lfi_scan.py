import re
import time
import random
import requests
import urllib3
import argparse
from colorama import Fore, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote  # Correct import for URL encoding
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Initialize colorama for colored console output
init(autoreset=True)

# List of User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
]

def get_random_user_agent():
    """
    Get a random User-Agent string from the predefined list.
    """
    return random.choice(USER_AGENTS)

def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    """
    Create a requests session with retry logic for transient errors.
    """
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def test_lfi(url, payloads, success_criteria, max_threads):
    """
    Test a URL for LFI vulnerabilities using the given payloads.
    """
    def check_payload(payload):
        """
        Check a single payload against the URL for LFI.
        """
        encoded_payload = quote(payload.strip())  # Correct URL encoding
        target_url = f"{url}{encoded_payload}"
        start_time = time.time()

        try:
            headers = {"User-Agent": get_random_user_agent()}
            # Disable automatic redirect following
            response = requests.get(target_url, headers=headers, verify=False, timeout=10, allow_redirects=False)
            response_time = round(time.time() - start_time, 2)
            result = None
            is_vulnerable = False

            if response.status_code in [301, 302]:
                # Handle redirects
                result = Fore.YELLOW + f"[→] Redirected: {Fore.RESET}{target_url} - Response Time: {response_time}s"
            elif response.status_code == 200:
                # Check response content against success criteria
                is_vulnerable = any(re.search(pattern, response.text) for pattern in success_criteria)
                if is_vulnerable:
                    result = Fore.GREEN + f"[✓] Vulnerable: {Fore.RESET}{target_url} - Response Time: {response_time}s"
                else:
                    result = Fore.RED + f"[✗] Not Vulnerable: {Fore.RESET}{target_url} - Response Time: {response_time}s"
            else:
                result = Fore.RED + f"[✗] Not Vulnerable: {Fore.RESET}{target_url} - Response Time: {response_time}s"

            return result, is_vulnerable
        except requests.exceptions.RequestException as e:
            return Fore.RED + f"[!] Error accessing {target_url}: {str(e)}", False

    found_vulnerabilities = 0
    vulnerable_urls = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_payload = {executor.submit(check_payload, payload): payload for payload in payloads}
        for future in as_completed(future_to_payload):
            payload = future_to_payload[future]
            try:
                print(Fore.YELLOW + f"[→] Scanning with payload: {payload.strip()}")
                result, is_vulnerable = future.result()
                if result:
                    print(result)
                    if is_vulnerable:
                        found_vulnerabilities += 1
                        vulnerable_urls.append(url + quote(payload.strip()))
            except Exception as e:
                print(Fore.RED + f"[!] Exception occurred for payload {payload}: {str(e)}")
    return found_vulnerabilities, vulnerable_urls

def run_lfi_scanner(urls, payloads, success_criteria, max_threads, output_file):
    """
    Run an LFI scanner against a list of URLs using a set of payloads.
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Results tracking
    total_found = 0
    total_scanned = 0
    vulnerable_urls = []

    if payloads:
        for url in urls:
            # Create a dynamic box for the current URL being scanned
            box_content = f" → Scanning URL: {url} "
            box_width = max(len(box_content) + 2, 40)
            print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
            print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
            print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n")

            # Call the test_lfi function for scanning
            found, urls_with_payloads = test_lfi(url, payloads, success_criteria, max_threads)
            total_found += found
            total_scanned += len(payloads)
            vulnerable_urls.extend(urls_with_payloads)

    # Save results to output file
    with open(output_file, "w") as f:
        if total_found > 0:
            f.write("Vulnerable URLs:\n")
            f.writelines(f"{url}\n" for url in vulnerable_urls)
        else:
            f.write("No vulnerabilities found.\n")

    # Summary
    print(Fore.GREEN + f"[✓] Scan completed. Total vulnerabilities found: {total_found}")
    print(Fore.CYAN + f"[→] Total URLs scanned: {len(urls)}")
    print(Fore.CYAN + f"[→] Total payloads tested: {total_scanned}")
    print(Fore.CYAN + f"[→] Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LFI Vulnerability Scanner")
    parser.add_argument("-l", "--list", required=True, help="File containing URLs")
    parser.add_argument("-p", "--payloads", required=True, help="File containing payloads")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("-o", "--output", required=True, help="Output file for results")

    args = parser.parse_args()

    # Read input files
    try:
        with open(args.list, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        with open(args.payloads, "r") as f:
            payloads = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        print(Fore.RED + f"[!] Error reading input file: {e}")
        exit(1)

    # Success criteria (adjust as needed)
    success_criteria = ["root:", "/etc/passwd", "boot"]

    # Run the scanner
    run_lfi_scanner(urls, payloads, success_criteria, args.threads, args.output)