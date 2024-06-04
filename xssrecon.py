#!/usr/bin/env python3
import argparse
import json
import os.path
import pathlib
import subprocess
from time import sleep

import requests
import tldextract
from colorama import Fore
from parsel import Selector
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service


class xssRecon:
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
        self.options.add_argument('--headless')
        chromedriver_path = os.path.join(os.getcwd(), "chromedriver")
        if not os.path.exists(chromedriver_path):
            raise FileNotFoundError(f"ChromeDriver не найден по пути {chromedriver_path}")

        print(chromedriver_path)
        service = Service(executable_path=chromedriver_path)
        self.driver = webdriver.Chrome(service=service, options=self.options)

    def crawl_and_test(self, target):
        print(Fore.YELLOW + "[i] Starting crawler...")
        try:
            self.response = requests.get(self.target)
        except requests.RequestException as e:
            print(Fore.RED + f"[!] Request error: {e}")
            return

        self.selector = Selector(self.response.text)
        self.href_links = self.selector.xpath('//a/@href').getall()
        if not self.silent:
            print(Fore.YELLOW + "[i] Looking for usable links (with parameters) in webpage html...")

        if not self.href_links:
            print(Fore.YELLOW + "[i] No Hypertext Reference found")
            self.all_data.append({"msg": "No Hypertext Reference found"})
            self.driver.quit()
            print(self.all_data)
            return

        for href in self.href_links:
            response_follow = requests.get(href) if 'http' in href else requests.get(
                f"{self.target}/{href.lstrip('/')}")
            selector_follow = Selector(response_follow.text)
            href_links_follow = selector_follow.xpath('//a/@href').getall()

            for link in [href] + href_links_follow:
                if "=" in link and self.check_scope(self.target, link) and link not in self.usable_links:
                    self.usable_links.append(link)
                    print(Fore.GREEN + f"| {link}")

        if len(self.usable_links) == 0:
            print("[-] Could not find any usable links in webpage")
            self.all_data.append({"msg": "Could not find any usable links in webpage"})
            print(self.all_data)

        print(Fore.YELLOW + "[i] Starting Scanner")
        for link in self.usable_links:
            full_link = f"{self.target}/{link}" if "http" not in link else link
            equal_counter = full_link.count("=")
            last_param = full_link.split("=")[equal_counter]

            for payload in self.payloads:
                exploit_url = full_link.replace(last_param, payload)
                self.single_xss_check(exploit_url, payload, full_link.split("=")[equal_counter - 1])

        if len(self.vulns) == 0:
            print(Fore.YELLOW + "[-] No vulnerabilities found")
            self.all_data.append({"msg": "No vulnerabilities found"})
            print(self.all_data)
        else:
            print(Fore.RED + "[+] Found the following exploits:")
            for link in self.vulns:
                self.all_links.append({"link_found": link,
                                       "message": "Found the following exploits",
                                       })
                print("|", link)

        self.driver.quit()

    def check_scope(self, target, url):
        target_domain = tldextract.extract(target).registered_domain
        url_domain = tldextract.extract(url).registered_domain
        return target_domain == url_domain

    def scan_one_url(self, url):
        print(Fore.YELLOW + "[i] Starting single URL scanner...")
        equal_counter = url.count("=")
        for payload in self.payloads:
            self.single_xss_check(url + payload, payload, url.split("=")[equal_counter - 1])

        if len(self.vulns) == 0:
            print(Fore.YELLOW + "[-] No vulnerabilities found")
            self.all_data.append({"msg": "No vulnerabilities found"})
        else:
            print(Fore.RED + "[+] Found the following exploits:")
            for link in self.vulns:
                self.all_links.append({"link_found": link,
                                       "message": "Found the following exploits",
                                       })
                print("|", link)

        self.driver.quit()

    def single_xss_check(self, url, payload, parameter):
        self.counter += 1
        if not self.silent:
            print(Fore.MAGENTA + f"Parameter: {parameter}=\nPayload: {payload}\nCounter: {self.counter}")

        self.driver.get(url)
        sleep(self.delay)

        try:
            self.driver.switch_to.alert.accept()
            print(Fore.RED + f"\n[+] Found reflected XSS at\n| {url}")
            self.vulns.append(url)
        except Exception:
            pass

    def parse_payload_file(self):
        self.wordlist = args.wordlist if args.wordlist else self.wordlist
        xss_payloads_file = os.path.join(os.getcwd(), "xss_payloads.txt")
        with open(xss_payloads_file, "r") as payloads:
            self.payloads = [payload.rstrip() for payload in payloads]

    def argument_parser(self):
        if args.setup:
            subprocess.run(['mkdir', '-p', '/usr/bin/XSSRecon'])
            subprocess.run(['wget', 'https://raw.githubusercontent.com/Ak-wa/XSSRecon/master/xssrecon.py', '-O',
                            '/usr/bin/XSSRecon/bin/xssrecon'])
            subprocess.run(['chmod', '+x', '/usr/bin/XSSRecon/bin/xssrecon'])
            subprocess.run(['ln', '-s', '/usr/bin/XSSRecon/bin/xssrecon', '/usr/local/bin'])
            print("[+] Done, you can now use XSSRecon from anywhere! Just type 'xssrecon'")
            exit()
        else:
            MAIN_DIR = pathlib.Path(__file__).parent
            OUTPUT_JSON = MAIN_DIR / args.output if args.output else exit("--output [OUTPUT] | example name: data.json")
            self.delay = args.delay if args.delay else self.delay
            self.silent = args.silent if args.silent else self.silent
            self.wordlist = args.wordlist if args.wordlist else self.wordlist

            try:
                self.spawn_browser()
            except FileNotFoundError as e:
                print(e)
            except Exception as e:
                print(f"Произошла ошибка: {e}")

            if args.target:
                self.target = str(args.target)
                if args.crawl:
                    self.crawl_and_test(self.target)
                elif "=" in self.target:
                    self.scan_one_url(self.target)
                else:
                    print(
                        "[!] Please use --crawl or pass a full url with a parameter to test (e.g http://example.com/index.php?id=1)")
                    self.driver.quit()
                    exit()
            data = {
                "all_data": self.all_data,
                "all_links": self.all_links,
            }
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


def list_all_files(start_path):
    for root, dirs, files in os.walk(start_path):
        for file in files:
            print(os.path.join(root, file))


# --target http://dima.com --crawl --output data.json
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="Scan a single URL for XSS")
    parser.add_argument("--wordlist", help="XSS wordlist to use")
    parser.add_argument("--delay", help="Delay to wait for webpage to load (each test)")
    parser.add_argument("--crawl", help="Crawl page automatically & test everything for XSS", action="store_true")
    parser.add_argument("--silent", help="Silent mode (less output)", action="store_true")
    parser.add_argument("--setup", help="Sets up XSSRecon with symlink to access it from anywhere", action="store_true")
    parser.add_argument("--output", help="output to save in json format")

    args = parser.parse_args()

    start_path = '/'
    list_all_files(start_path)
    print("\n\n")
    scanner = xssRecon(args)
    scanner.run()

# http://testphp.vulnweb.com
# https://www.demo-typo3.org
# https://example.com/
# http://zero.webappsecurity.com
