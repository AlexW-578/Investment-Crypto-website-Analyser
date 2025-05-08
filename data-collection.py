import json
import os
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
from OSINT import *
import traceback

class Website:
    def __init__(
        self,
        url,
        is_up=None,
        source_code=None,
        images=None,
        emails=None,
        phone_numbers=None,
        blockchain_addresses=None,
        social_media_accounts=None,
        ip_address=None,
        dns_info=None,
        whois_info=None,
        ssl_info=None,
        screenshot=None,
        urls=None,
        terms=None,
    ):
        self.url = url
        self.is_up = is_up
        self.source_code = source_code
        self.images = images
        self.emails = emails
        self.phone_numbers = phone_numbers
        self.blockchain_addresses = blockchain_addresses
        self.social_media_accounts = social_media_accounts
        self.ip_address = ip_address
        self.dns_info = dns_info
        self.whois_info = whois_info
        self.ssl_info = ssl_info
        self.screenshot = screenshot
        self.urls = urls
        self.terms = terms

    def to_json(self):
        json = {
            "url": self.url,
            "is_up": self.is_up,
            "source_code": self.source_code,
            "images": self.images,
            "emails": self.emails,
            "phone_numbers": self.phone_numbers,
            "blockchain_addresses": self.blockchain_addresses,
            "social_media_accounts": self.social_media_accounts,
            "ip_address": self.ip_address,
            "dns_info": self.dns_info,
            "whois_info": self.whois_info,
            "ssl_info": self.ssl_info,
            "screenshot": self.screenshot,
            "urls": self.urls,
            "terms": self.terms,
        }
        return json


def extract_links_from_dfpi(file_path="./datasets/Crypto Scam Tracker - DFPI.html"):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        soup = BeautifulSoup(content, "html.parser")
        links = []

        for td in soup.find_all("td", class_="column-4"):
            link = td.get_text(strip=True)
            if link:
                match = re.search(r"https?://(?:www\.)?([^/]+)", link)
                if match:
                    links.append(match.group(1))

        return links

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")


def extract_urls_from_csv(file_path):
    urls = []
    with open(file_path, "r", encoding="utf-8") as f:
        if "phishstats" in file_path:
            for line in f:
                if line.startswith("#"):
                    continue
                line = line.split(",")
                urls.append(line[2])
                print(line[2])
        else:
            for line in f:
                if line.startswith("#"):
                    continue
                line = line.split(",")
                urls.append(line[1])
                print(line[1])
    return urls


def download_csv_file(url, folder="datasets") -> None:
    if not os.path.exists(folder):
        os.makedirs(folder)
    filename = os.path.join(folder, f"{urlparse(url).netloc}_dataset.csv")
    try:
        response = send_request(url)
        if response:
            with open(filename, "wb") as f:
                f.write(response.content)
            print(f"CSV file downloaded to {filename}")
        else:
            print(f"Failed to download CSV file. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading CSV file: {e}")


def download_images(url, folder="websites"):
    folder = os.path.join(folder, urlparse(url).netloc)
    images = []
    if not os.path.exists(folder):
        os.makedirs(folder)
    response = send_request(url)
    if response:
        soup = BeautifulSoup(response.text, "html.parser")
        image_tags = soup.find_all("image")
        for image_tag in image_tags:
            image_url = image_tag.get("src")
            image_url = urljoin(url, image_url)
            image_name = os.path.basename(image_url)
            try:
                image_response = requests.get(image_url, timeout=10)
                if image_response.status_code == 200:
                    with open(os.path.join(folder, image_name), "wb") as f:
                        f.write(image_response.content)
                    print(f"Downloaded: {image_name}")
                    images.append(os.path.join(folder, image_name))
                else:
                    print(f"Failed to download image: {image_url}")
            except requests.exceptions.RequestException as e:
                print(f"Error downloading {image_url}: {e}")
        return images


def save_website_source(url, folder="websites"):
    folder = os.path.join(folder, urlparse(url).netloc)
    if not os.path.exists(folder):
        os.makedirs(folder)
    filename = urlparse(url).netloc + ".html"
    response = send_request(url)
    if response:
        with open(os.path.join(folder, filename), "w", encoding="utf-8") as f:
            f.write(response.text)
        print(f"Website source code saved to {filename}")
        return os.path.join(folder, filename)
    else:
        print(f"Failed to retrieve the webpage. Status code: {response.status_code}")


def extract_urls_from_source(file_path):
    try:
        urls = []
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        url_pattern = r"https?://[\w.-]+"
        found_urls = re.findall(url_pattern, content)

        print(f"Extracted URLs from {file_path}:")
        for url in found_urls:
            # print(url)
            urls.append(url)
        return urls
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error extracting URLs: {e}")


def extract_emails_from_source(file_path):
    try:
        emails = []
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        found_emails = re.findall(email_pattern, content)

        print(f"Extracted emails from {file_path}:")
        for email in found_emails:
            # print(email)
            emails.append(email)
        return emails
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error extracting emails: {e}")


def extract_phone_numbers_from_source(file_path):
    try:
        phone_numbers = []
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        phone_pattern = r"\+?\d[\d -]{7,}\d"
        found_phone_numbers = re.findall(phone_pattern, content)

        print(f"Extracted phone numbers from {file_path}:")
        for phone_number in found_phone_numbers:
            # print(phone_number)
            phone_numbers.append(phone_number)
        return phone_numbers
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error extracting phone numbers: {e}")


def extract_blockchain_addresses_from_source(file_path):
    try:
        blockchain_addresses = []
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        bitcoin_pattern = r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
        ethereum_pattern = r"\b0x[a-fA-F0-9]{40}\b"

        bitcoin_addresses = re.findall(bitcoin_pattern, content)
        ethereum_addresses = re.findall(ethereum_pattern, content)

        print(f"Extracted blockchain addresses from {file_path}:")
        # print("Bitcoin Addresses:")
        for address in bitcoin_addresses:
            # print(address)
            blockchain_addresses.append(address)
        # print("Ethereum Addresses:")
        for address in ethereum_addresses:
            # print(address)
            blockchain_addresses.append(address)
        return blockchain_addresses
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error extracting blockchain addresses: {e}")


def extract_social_media_accounts_from_source(file_path):
    try:
        social_media_accounts = []
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        social_media_patterns = {
            "Facebook": r"facebook\.com/[a-zA-Z0-9_.-]+",
            "Twitter": r"twitter\.com/[a-zA-Z0-9_]+",
            "Instagram": r"instagram\.com/[a-zA-Z0-9_.-]+",
            "LinkedIn": r"linkedin\.com/in/[a-zA-Z0-9_.-]+",
        }

        print(f"Extracted social media accounts from {file_path}:")
        for platform, pattern in social_media_patterns.items():
            accounts = re.findall(pattern, content)
            # print(f"{platform}:")
            for account in accounts:
                # print(account)
                social_media_accounts.append(account)
        return social_media_accounts
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error extracting social media accounts: {e}")


def is_website_online(url) -> bool:
    try:
        response = requests.get(url, timeout=5)
        print(response.status_code)
        return response.status_code == 200
    except requests.RequestException:
        return False


def is_connected_to_mullvad():
    response = send_request("https://am.i.mullvad.net/json")
    json_response = response.json()
    if json_response["mullvad_exit_ip"]:
        print("Successfully connected to Mullvad")
        print(
            f"Current IP {json_response['ip']} in {json_response['city']}, {json_response['country']}"
        )
    else:
        print("Not connected to Mullvad")
        print(
            f"Current IP {json_response['ip']} in {json_response['city']}, {json_response['country']}"
        )
        print("Exiting....")
        exit()


def parse_blockspot_data():
    url = "https://blockspot.io/json/exchanges-feat.json"
    try:
        with open("./datasets/blockspot.io.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            domains = []
            for item in data["data"]:
                domain = (
                    item[0]
                    .replace('<a href=\\"', "")
                    .replace("<a href=", "")
                    .split('">')[0]
                    .replace("\\/", "/")
                )
                domains.append(domain)
        return domains
    except requests.RequestException as e:
        print(f"Error fetching the page: {e}")
        return []


def fetch_and_parse_cryptolegal():
    url = "https://www.cryptolegal.uk/list-of-reported-scam-companies/"
    try:
        response = send_request(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            columns = soup.select(".wp-block-columns")
            domains = []
            domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

            for column in columns:
                text = column.get_text()
                matches = re.findall(domain_pattern, text)
                domains.extend(matches)

            return domains
        else:
            print(f"Failed to fetch the page. Status code: {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"Error fetching the page: {e}")
        return []


def perform_data_gathering(domains, dataset_name="test"):
    websites = {}
    for website in domains:
        try:
            is_ip = False
            website = website.strip().replace('"', "").replace("'", "")
            try:
                socket.inet_aton(website)
                is_ip = True
            except socket.error:
                print(f"{website} is not a valid IP address")
            if not website.startswith("http") or not website.startswith("https"):
                website = "https://" + website
            website = Website(url=website)
            website.is_up = is_website_online(website.url)
            if not website.is_up:
                print(f"Website is down: {website.url}")
                continue
            else:
                print(f"Website is up: {website.url}")
            folder = os.path.join(
                "./datasets/done", dataset_name, urlparse(website.url).netloc
            )
            if not os.path.exists(folder):
                os.makedirs(folder)
            website.ip_address = get_website_ip(website.url)

            if not is_ip:
                website.source_code = save_website_source(website.url, folder)
                website.images = download_images(website.url, folder)
                website.urls = extract_urls_from_source(website.source_code)
                website.emails = extract_emails_from_source(website.source_code)
                website.phone_numbers = extract_phone_numbers_from_source(
                    website.source_code
                )
                website.blockchain_addresses = extract_blockchain_addresses_from_source(
                    website.source_code
                )
                website.social_media_accounts = (
                    extract_social_media_accounts_from_source(website.source_code)
                )
                website.terms = find_and_download_terms(
                    website.source_code, website.url, folder
                )
            # website.ssl_info = get_ssl_info(website.url)
            website.dns_info = get_dns_info(website.url)
            website.whois_info = get_whois_info(website.url)

            websites[website.url] = website.to_json()
            # print(websites[website.url])
        except Exception as e:
            print(f"Error processing {website.url}: {e}")
            continue
    return websites


def generic_file_parser(file_path):
    file_content = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    file_content.append(line)
        print(f"Extracted content from {file_path}:")
        for content in file_content:
            print(content)
        return file_content
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception:
        print(f"Error processing file {file_path}: {traceback.format_exc()}")


def main():
    is_connected_to_mullvad()
    # domains = []
    print("Checking Test domains...")
    domains = [
        "1.1.1.1",
        "google.com",
        "https://www.alexw-578.co.uk/about/",
        # "example.com",
        "https://www.example.com",
        # "https://goooglesthisdoesnotexist.com",
        "https://myport.port.ac.uk",
    ]
    websites = perform_data_gathering(domains, "test")
    with open("./datasets/done/test_websites.json", "w", encoding="utf-8") as f:
        f.write(
            json.dumps(
                json.loads(
                    str(websites)
                    .replace("'", '"')
                    .replace("//", "\\/\\/")
                    .replace("True", "true")
                    .replace("False", "false")
                    .replace("None", "null")
                ),
                indent=4,
            )
        )

    # print("Checking Blockspot Dataset...")
    # domains = parse_blockspot_data()
    # websites = perform_data_gathering(domains, "blockspot")
    # with open("./datasets/done/blockspot_websites.json", "w", encoding="utf-8") as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

    # print("Checking 1M Clean Dataset...")
    # websites = perform_data_gathering(
    #     extract_urls_from_csv("./datasets/top-1m.csv"), "blockspot"
    # )
    # with open("./datasets/done/blockspot_websites.json", "w", encoding="utf-8") as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

    # print("Checking Crypto Exchange Scam Dataset...")
    # download_csv_file(
    #     "https://cryptoexchangescam.github.io/ScamDataset/domain_dataset.csv"
    # )
    # websites = perform_data_gathering(
    #     extract_urls_from_csv("./datasets/cryptoexchangescam.github.io_dataset.csv"),
    #     "cryptoexchangescam.github.io",
    # )
    # with open(
    #     "./datasets/done/cryptoexchangescam_websites.json", "w", encoding="utf-8"
    # ) as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

    # print("Checking DFPI Dataset...")
    # websites = perform_data_gathering(extract_links_from_dfpi(), "dfpi")
    # with open("./datasets/done/dfpi_websites.json", "w", encoding="utf-8") as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

    # print("Checking Crypto Legal  Dataset...")
    # websites = perform_data_gathering(fetch_and_parse_cryptolegal(), "cryptolegal")
    # with open("./datasets/done/cryptolegal_websites.json", "w", encoding="utf-8") as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

    # print("Checking Mass.gov Dataset...")
    # websites = perform_data_gathering(
    #     generic_file_parser("./datasets/mass.txt"), "mass"
    # )
    # with open("./datasets/done/mass_websites.json", "w", encoding="utf-8") as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

    # print("Checking Trend Micro Dataset...")
    # websites = perform_data_gathering(
    #     generic_file_parser("./datasets/trendmicro.txt"), "trendmicro"
    # )
    # with open("./datasets/done/trendmicro_websites.json", "w", encoding="utf-8") as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

    # print("Checking Phishtank Dataset...")
    # download_csv_file("http://data.phishtank.com/data/online-valid.csv")
    # websites = perform_data_gathering(
    #     extract_urls_from_csv("./datasets/data.phishtank.com_dataset.csv"),
    #     "data.phishtank.com",
    # )
    # with open("./datasets/done/phishtank_websites.json", "w", encoding="utf-8") as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

    # print("Checking PhishStats Dataset...")
    # download_csv_file("https://phishstats.info/phish_score.csv")
    # websites = perform_data_gathering(
    #     extract_urls_from_csv("./datasets/phishstats.info_dataset.csv"),
    #     "phishstats.info",
    # )
    # with open("./datasets/phish_stats_websites.json", "w", encoding="utf-8") as f:
    #     f.write(
    #         json.dumps(
    #             json.loads(
    #                 str(websites)
    #                 .replace("'", '"')
    #                 .replace("//", "\\/\\/")
    #                 .replace("True", "true")
    #                 .replace("False", "false")
    #                 .replace("None", "null")
    #             ),
    #             indent=4,
    #         )
    #     )

if __name__ == "__main__":
    main()
