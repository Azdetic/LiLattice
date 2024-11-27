import os
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import validators
import logging
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor

# Set up logging to save activity logs
logging.basicConfig(filename='website_analysis.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to check SSL certificate
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        logging.info(f"SSL certificate found for {domain}")
        return f"Valid until: {cert['notAfter']}"
    except Exception as e:
        logging.error(f"Error checking SSL: {e}")
        return "Cannot validate SSL certificate."

# Function to analyze a website
def analyze_website(url):
    try:
        # Validate URL
        if not validators.url(url):
            return "Invalid URL. Please enter a URL with http:// or https://"
        if not urlparse(url).netloc:
            return "Invalid URL. No domain detected."

        # Send a GET request to the URL
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract basic information
        forms = soup.find_all('form')
        input_fields = soup.find_all('input')
        links = soup.find_all('a', href=True)
        headers = response.headers

        # Initialize report
        report = f"Analyzing: {url}\n\n"
        report += f"Found {len(forms)} forms on the page.\n"
        report += f"Found {len(input_fields)} input fields.\n"
        report += f"Found {len(links)} links on the page.\n"

        # Analyze HTTP headers for security weaknesses
        weaknesses = []
        if 'X-Frame-Options' not in headers:
            weaknesses.append("X-Frame-Options header not found - clickjacking risk.")
        if 'Strict-Transport-Security' not in headers:
            weaknesses.append("Strict-Transport-Security header not found - HTTPS not enforced, HTTP is allowed.")
        if 'Content-Security-Policy' not in headers:
            weaknesses.append("Content-Security-Policy header not found - cross-site scripting risk (XSS).")

        # Analyze forms
        for form in forms:
            action = form.get('action')
            method = form.get('method', '').lower()
            if not action or not action.startswith(('https', 'http')):
                weaknesses.append(f"Form with action '{action}' is not secure (uses HTTP or no action).")
            if method == 'get':
                weaknesses.append(f"Form with GET method found - user data will be exposed in URL: {action}")

        # Analyze input fields
        for input_field in input_fields:
            input_type = input_field.get('type', '').lower()
            input_name = input_field.get('name', '').lower()
            if input_type == 'text':
                weaknesses.append("Text input field found - potential SQL Injection risk.")
            if 'password' in input_name:
                weaknesses.append("Input field with 'password' found - data leakage risk if not encrypted.")
            if 'email' in input_name or 'username' in input_name:
                weaknesses.append(f"Input field with name '{input_name}' found - ensure server-side validation.")

        # Analyze external links
        external_links = [urljoin(url, link['href']) for link in links if urlparse(link['href']).netloc != urlparse(url).netloc]
        report += f"Found {len(external_links)} external links.\n\n"

        # Details about external links
        report += "External Links Found:\n"
        dead_links = []

        def check_link(link):
            try:
                res = requests.head(link, timeout=5)
                if res.status_code >= 400:
                    dead_links.append(link)
                    return f"{link} (Dead - Status Code: {res.status_code})"
                else:
                    if "https" not in link:
                        weaknesses.append(f"Link {link} does not use HTTPS - insecure for communication.")
                    return f"{link} (Active)"
            except Exception:
                dead_links.append(link)
                return f"{link} (No response)"

        # Check links in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=5) as executor:
            link_statuses = list(executor.map(check_link, external_links))

        report += "\n".join(link_statuses) + "\n"

        # Analyze SSL certificate
        domain = urlparse(url).netloc
        ssl_info = check_ssl(domain)
        if "Cannot validate" in ssl_info:
            weaknesses.append(f"SSL certificate is invalid or not found for domain {domain}.")
        report += f"\nSSL Information: {ssl_info}\n"

        # Report potential weaknesses
        report += "\nPotential Weaknesses:\n"
        if weaknesses:
            for item in weaknesses:
                report += f"- {item}\n"
        else:
            report += "No clear weaknesses found.\n"

        # Save the report
        folder = "reports"
        os.makedirs(folder, exist_ok=True)
        file_name = f"{folder}/Website_Analysis_{domain.replace('.', '_')}.txt"
        with open(file_name, 'w') as file:
            file.write(report)

        logging.info(f"Report successfully saved: {file_name}")
        return f"Analysis complete. Report saved at {file_name}."

    except requests.exceptions.Timeout:
        return "Request failed due to timeout. Try again later."
    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP error: {e}")
        return f"Failed to access URL: {e}"
    except Exception as e:
        logging.error(f"General error: {e}")
        return f"An error occurred: {e}"

# Main menu
def menu():
    while True:
        print("\n==== Menu ====")
        print("1. Analyze Website")
        print("2. Show Activity Log")
        print("3. Exit")
        choice = input("Choose an option (1/2/3): ").strip()

        if choice == "1":
            website_url = input("Enter the URL of the website to analyze: ").strip()
            if not website_url:
                print("URL cannot be empty.")
            else:
                result = analyze_website(website_url)
                print(result)

        elif choice == "2":
            print("\nActivity Log:")
            try:
                with open("website_analysis.log", "r") as log_file:
                    print(log_file.read())
            except FileNotFoundError:
                print("Log not available yet.")

        elif choice == "3":
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please choose 1-3.")

# Run the main menu
if __name__ == "__main__":
    menu()
