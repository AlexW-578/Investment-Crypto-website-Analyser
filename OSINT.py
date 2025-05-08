import requests
import socket
import dns.resolver
import whois
import ssl
import re
import os
from urllib.parse import urljoin, urlparse
import datetime
from bs4 import BeautifulSoup


def send_request(url, headers={}) -> requests.Response:
    if headers == {} or headers["User-Agent"] is None:
        headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
        )
    response = requests.get(url, timeout=10, headers=headers)
    return response

def find_and_download_terms(file_path, url, folder="websites"):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        soup = BeautifulSoup(content, "html.parser")
        terms_links = []

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if re.search(r"(terms|conditions|policy|legal)", href, re.IGNORECASE):
                terms_links.append(urljoin(url, href))

        downloaded_files = []
        for link in terms_links:
            try:
                terms_response = send_request(link)
                if terms_response.status_code == 200:
                    filename = os.path.join(
                        folder,
                        os.path.basename(urlparse(link).path) or "terms.html",
                    )
                    if not filename.endswith(".html"):
                        filename += ".html"
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(terms_response.text)
                    print(f"Downloaded terms and conditions page: {filename}")
                    downloaded_files.append(filename)
            except Exception as e:
                print(f"Error downloading terms page {link}: {e}")
        return downloaded_files
    except Exception:
        return []



def get_website_ip(url):
    try:
        hostname = urlparse(url).netloc
        print(f"Getting IP address for {url}")
        return socket.gethostbyname(hostname)
    except Exception as e:
        print(f"Error getting IP for {url}: {e}")
        return None


def get_dns_info(domain):
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc
    dns_info = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    print(f"Gathering DNS information for {domain}")
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
            if record_type == "TXT":
                dns_info[record_type] = [
                    rdata.to_text().replace('"', "") for rdata in answers
                ]
            else:
                dns_info[record_type] = [rdata.to_text() for rdata in answers]
        except Exception:
            dns_info[record_type] = []
    return dns_info


def get_whois_info(url):
    try:
        domain = urlparse(url).netloc or url
        whois_data = whois.whois(domain)
        print(f"Downloaded WHOIS information: {url}")
        for key, value in whois_data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, datetime.datetime):
                        whois_data[key] = item.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(value, datetime.datetime):
                whois_data[key] = value.strftime("%Y-%m-%d %H:%M:%S")
        return whois_data
    except Exception as e:
        print(f"Error retrieving WHOIS info for {url}: {e}")
        return None


def get_ssl_info(url):
    try:
        if urlparse(url).scheme is None or urlparse(url).scheme == "http":
            return None
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_info = {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "organizationName": cert.get("organizationName"),
                    "commonName": cert.get("commonName"),
                    # "countryName": cert.get("countryName"),
                    "version": cert.get("version"),
                    "serialNumber": cert.get("serialNumber"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "subkectAltName": cert.get("subjectAltName"),
                    "OCSP": cert.get("OCSP"),
                    "caIssuers": cert.get("caIssuers"),
                    "crlDistributionPoints": cert.get("crlDistributionPoints"),
                }
                print(f"Downloaded SSL certificate information: {url}")
                return cert_info
    except Exception as e:
        print(f"Error retrieving SSL info for {url}: {e}")
        return None
