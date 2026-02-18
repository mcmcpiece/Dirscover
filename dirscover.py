#!/bin/python
import argparse
import requests
import string
import random
from bs4 import BeautifulSoup
from pyfiglet import Figlet

def httpresp_scan_200check(i, url, response):
    #Compares http response length of url+i vs url+random_string
    if (len(response.text) - len(i)) == (len(requests.get(url+"hshshedhhfcuueeiisisiaow").text) - len("hshshedhhfcuueeiisisiaow")):
        print(f"A possible false positive at {url}{i}")
    elif (len(response.text) - len(i)) != (len(requests.get(url+"hshshedhhfcuueeiisisiaow").text) - len("hshshedhhfcuueeiisisiaow")):
        print(f"[HTTP {response.status_code}] - Possible directory found: {url}{i}")

def httpresp_scan_300check(i, url, response):
    #get requests for checking
    url_to_scan = url + i.strip()
    r = requests.get(url_to_scan)
    if r.text != requests.get(url+"gsgshsheheh").text:
        print(f"Redirect found with {url}{i} >> {r.url}")
    elif r.text == requests.get(url+"gsgshsheheh").text:
        return


def httpresp_scan(wlist, url, args):
    #Performs attack by interpretting http response codes
    print(f"Discovering directories for {url}...")
    responses = []
    for i in wlist:
        print(f"Seeing if {i.strip()} exists...")
        response = requests.get(url + i.strip(), allow_redirects=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        if 200 <= response.status_code <= 299:
            if not soup.find("meta", attrs={"http-equiv":"refresh"}):
                httpresp_scan_200check(i, url, response)
        elif 300 <= response.status_code <= 399:
            if args.accept300:
                continue
            else:
                httpresp_scan_300check(i, url, response)
        elif 400 <= response.status_code <= 499:
            continue
        elif 500 <= response.status_code <= 599:
            print(f"Restricted access at {url}{i}")

def httplength_scan(wlist, url):
    print(f"Running httplength scan with {url}")
    #Making an intentional bad request and using its text lengtb as reference for a page not found
    random_string = ''.join(random.choice(string.ascii_letters) for _ in range(10))
    fake_request = requests.get(url+random_string)
    html = fake_request.text
    soup = BeautifulSoup(html, "html.parser")
    fake_length = len(soup.text)
    
    #Making the actual attempts
    for i in wlist:
        print(f"Seeing if {url}{i}")
        response = requests.get(url+i.strip())
        response_html = response.text
        response_soup = BeautifulSoup(response_html, "html.parser")
        response_length = len(response_soup.text)
        if response_length == fake_length:
            continue
        else:
            print(f"Possible directory found at {url}{i.strip()}")
    

def main():

    parse = argparse.ArgumentParser(description="DirsCover.py | Scans and looks for possible web directories. Useful for reconnaisance.")
    parse.add_argument("wordlist", help="File to use as wordlist. Use \'-d\' for default wordlist (commons.txt)")
    parse.add_argument("url", help="Root directory of the website. If you encounter an error, try adding the specific port number to this argument, Otherwise, it defaults to port 80 for http and port 443 for https.")
    parse.add_argument("--mode", help="Defines which mode to run: httpresp (scans which directory returns a 200 OK response from the server) | httplength (scans the length of the http response per directory and returns the one with the significant difference)", default="httpresp")
    parse.add_argument("--accept300", help="Accepts all HTTP 3XX responses and printing the final URL for the redirects. Disabled by default to focus only on HTTP 2XX responses", action="store_false")
    args=parse.parse_args()
    
    #opening wlist as a file and interpretting functions

    wfile = open(args.wordlist, "r")
    
    if args.mode.lower() == "httpresp":
        httpresp_scan(wfile, args.url, args)
    elif args.mode.lower() == "httplength":
        httplength_scan(wfile, args.url)
    else:
        print(f"Mode can't be {args.mode}")

if __name__=="__main__":
    try:
        #Making the title and running main function()
        f = Figlet(font="efti_robot")
        print(f.renderText("Dirscover.py"))
        main()
    except KeyboardInterrupt:
        print("\nDid you mean to exit? Exiting now...")
        exit()
