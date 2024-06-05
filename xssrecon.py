#!/usr/bin/env python3
import argparse
import contextlib
import json
import os
import os.path
import pathlib
import subprocess
from time import sleep

import requests
import tldextract
from colorama import Fore
from parsel import Selector
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service


# --target http://dima.com --crawl --output data.json
class XssRecon:
    def __init__(self, arguments):
        self.target = ""
        self.silent = False
        self.target_links = []
        self.payloads = []
        self.vulns = []
        self.usable_links = []
        self.counter = 0
        self.wordlist = "xss_payloads.txt"
        self.delay = 0
        self.used_parameters = []
        self.all_data = []
        self.all_links = []

    def spawn_browser(self):
        self.options = Options()
        self.options.add_argument("--headless")

        # self.profile = webdriver.FirefoxProfile()
        # self.profile.set_preference("permissions.default.image", 2)
        # self.profile.set_preference("permissions.default.stylesheet", 2)

        webdriver_service = Service(
            # executable_path="/usr/bin/geckodriver",
            # executable_path="geckodriver",
            executable_path="/usr/bin/geckodriver",
        )

        self.driver = webdriver.Firefox(
            service=webdriver_service,
            options=self.options,
            # profile=self.profile,
        )

    def crawl_and_test(self, target):
        print(f"{Fore.YELLOW}[i] Starting crawler...")
        try:
            self.response = requests.get(self.target)
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Request error: {e}")
            return

        self.selector = Selector(self.response.text)
        self.href_links = self.selector.xpath("//a/@href").getall()
        if not self.silent:
            print(
                Fore.YELLOW
                + "[i] Looking for usable links (with parameters) in webpage html..."
            )

        if not self.href_links:
            print(f"{Fore.YELLOW}[i] No Hypertext Reference found")
            self.all_data.append({"msg": "No Hypertext Reference found"})
            self.driver.quit()
            return

        for href in self.href_links:
            response_follow = (
                requests.get(href)
                if "http" in href
                else requests.get(f"{self.target}/{href.lstrip('/')}")
            )
            selector_follow = Selector(response_follow.text)
            href_links_follow = selector_follow.xpath("//a/@href").getall()

            for link in [href] + href_links_follow:
                if (
                        "=" in link
                        and self.check_scope(self.target, link)
                        and link not in self.usable_links
                ):
                    self.usable_links.append(link)
                    print(f"{Fore.GREEN}| {link}")

        if len(self.usable_links) == 0:
            print("[-] Could not find any usable links in webpage")
            self.all_data.append({"msg": "Could not find any usable links in webpage"})

        print(f"{Fore.YELLOW}[i] Starting Scanner")
        for link in self.usable_links:
            full_link = f"{self.target}/{link}" if "http" not in link else link
            equal_counter = full_link.count("=")
            last_param = full_link.split("=")[equal_counter]

            for payload in self.payloads:
                exploit_url = full_link.replace(last_param, payload)
                self.single_xss_check(
                    exploit_url, payload, full_link.split("=")[equal_counter - 1]
                )

        if len(self.vulns) == 0:
            print(f"{Fore.YELLOW}[-] No vulnerabilities found")
            self.all_data.append({"msg": "No vulnerabilities found"})
        else:
            print(f"{Fore.RED}[+] Found the following exploits:")
            for link in self.vulns:
                self.all_links.append(
                    {
                        "link_found": link,
                        "message": "Found the following exploits",
                    }
                )
                print("|", link)

        self.driver.quit()

    def check_scope(self, target, url):
        target_domain = tldextract.extract(target).registered_domain
        url_domain = tldextract.extract(url).registered_domain
        return target_domain == url_domain

    def scan_one_url(self, url):
        print(f"{Fore.YELLOW}[i] Starting single URL scanner...")
        equal_counter = url.count("=")
        for payload in self.payloads:
            self.single_xss_check(
                url + payload, payload, url.split("=")[equal_counter - 1]
            )

        if len(self.vulns) == 0:
            print(f"{Fore.YELLOW}[-] No vulnerabilities found")
            self.all_data.append({"msg": "No vulnerabilities found"})
        else:
            print(f"{Fore.RED}[+] Found the following exploits:")
            for link in self.vulns:
                self.all_links.append(
                    {
                        "link_found": link,
                        "message": "Found the following exploits",
                    }
                )
                print("|", link)

        self.driver.quit()

    def single_xss_check(self, url, payload, parameter):
        self.counter += 1
        if not self.silent:
            print(
                Fore.MAGENTA
                + f"Parameter: {parameter}=\nPayload: {payload}\nCounter: {self.counter}"
            )

        self.driver.get(url)
        sleep(self.delay)

        with contextlib.suppress(Exception):
            self.driver.switch_to.alert.accept()
            print(f"{Fore.RED}\n[+] Found reflected XSS at\n| {url}")
            self.vulns.append(url)

    def parse_payload_file(self):
        self.wordlist = args.wordlist or self.wordlist
        xss_payloads_file = os.path.join(os.getcwd(), "xss_payloads.txt")
        with open(xss_payloads_file, "r") as payloads:
            self.payloads = [payload.rstrip() for payload in payloads]

    def argument_parser(self):
        if args.setup:
            subprocess.run(["mkdir", "-p", "/usr/bin/XSSRecon"])
            subprocess.run(
                [
                    "wget",
                    "https://raw.githubusercontent.com/Ak-wa/XSSRecon/master/xssrecon.py",
                    "-O",
                    "/usr/bin/XSSRecon/bin/xssrecon",
                ]
            )
            subprocess.run(["chmod", "+x", "/usr/bin/XSSRecon/bin/xssrecon"])
            subprocess.run(
                ["ln", "-s", "/usr/bin/XSSRecon/bin/xssrecon", "/usr/local/bin"]
            )
            print(
                "[+] Done, you can now use XSSRecon from anywhere! Just type 'xssrecon'"
            )
            exit()
        else:
            MAIN_DIR = pathlib.Path(__file__).parent
            OUTPUT_JSON = (
                MAIN_DIR / args.output
                if args.output
                else exit("--output [OUTPUT] | example name: data.json")
            )
            self.delay = args.delay or self.delay
            self.silent = args.silent or self.silent
            self.wordlist = args.wordlist or self.wordlist

            self.spawn_browser()

            if args.target:
                self.target = str(args.target)
                if args.crawl:
                    self.crawl_and_test(self.target)
                elif "=" in self.target:
                    self.scan_one_url(self.target)
                else:
                    print(
                        "[!] Please use --crawl or pass a full url with a parameter to test (e.g http://example.com/index.php?id=1)"
                    )
                    self.driver.quit()
                    exit()
            if self.all_data == [] and self.all_links == []:
                data = {
                    "Request_error": "Unable to connect to the site. The server is not responding. Please try again later."
                }
            else:
                data = {
                    "all_data": self.all_data,
                    "all_links": self.all_links,
                }
            print(data)
            with open(OUTPUT_JSON, "w") as jf:
                json.dump(data, jf, indent=2)

    def run(self):
        try:
            self.parse_payload_file()
            self.argument_parser()
            print(json.dumps(self.all_data, indent=2))  # Вывод данных в терминал
        except KeyboardInterrupt:
            print(Fore.GREEN + "\n[-] CTRL-C caught, exiting...")
            self.driver.quit()
            exit()
        except Exception as e:
            print(e)
            self.driver.quit()
            exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="Scan a single URL for XSS")

    parser.add_argument("--wordlist", help="XSS wordlist to use")
    parser.add_argument("--delay", help="Delay to wait for webpage to load (each test)")
    parser.add_argument(
        "--crawl",
        help="Crawl page automatically & test everything for XSS",
        action="store_true",
    )
    parser.add_argument(
        "--silent", help="Silent mode (less output)", action="store_true"
    )
    parser.add_argument(
        "--setup",
        help="Sets up XSSRecon with symlink to access it from anywhere",
        action="store_true",
    )
    parser.add_argument("--output", help="output to save in json format")

    args = parser.parse_args()

    scanner = XssRecon(args)
    scanner.run()

# http://testphp.vulnweb.com
# https://www.demo-typo3.org
# https://example.com/
# http://zero.webappsecurity.com
