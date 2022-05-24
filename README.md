# CF-Clearance-Scraper

A simple program for fetching cf_clearance cookies from websites issuing cloudflare challenges to users. This program works on JavaScript and (non-interactive) managed challenges. 

#### Please Note
This scraper cannot solve CAPTCHA challenges since human interaction would be required.

## Clearance Cookie Usage
In order to bypass cloudflare challenges with the cloudflare clearance cookies, you must make sure of two things:

- The user agent used to fetch the clearance cookie must match the user agent being used within the requests that use the clearance cookie (You can edit the user agent used by the scraper by changing the ```user_agent``` variable on line 10)
- The IP address used to fetch the clearance cookie must match the IP address being used to make the requests that use the clearance cookie

```mermaid
flowchart
	N14e["cf_clearance"]
	N14f["IP Address"]
	N150["User Agent"]
	N14e --> N14f
	N14e --> N150
```

## Installation
```
pip3 install -r requirements.txt
```

#### Mac | Windows
```
npm install playwright
```

#### Linux
```
npm install playwright
playwright install-deps
```

## Usage
```
usage: cf_cookie.py [-h] [-v] [-u URL] [-f FILE] [-t TIMEOUT] [-p PROXY]

Fetches cf_clearance cookies from websites issuing cloudflare challenges to users

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose logging
  -u URL, --url URL     URL to fetch cf_clearance cookie from
  -f FILE, --file FILE  File to write the cf_clearance cookie value to
  -t TIMEOUT, --timeout TIMEOUT
                        Cookie fetch timeout (milliseconds)
  -p PROXY, --proxy PROXY
                        Proxy server to use for requests (Authentification not
                        supported). Example: socks5://172.66.43.144:1080
```
```
Example: python3 cf_cookie.py -u https://nowsecure.nl -f cookies.txt -v
```
