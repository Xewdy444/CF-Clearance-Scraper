# CF-Clearance-Scraper

## Playwright Version
A simple program for scraping Cloudflare clearance (cf_clearance) cookies from websites issuing Cloudflare challenges to visitors. This program works on all Cloudflare challenge types (JavaScript, managed, and interactive). If you would prefer using nodriver, you can check out the [nodriver version](https://github.com/Xewdy444/CF-Clearance-Scraper/tree/nodriver).

## Clearance Cookie Usage
In order to bypass Cloudflare challenges with the clearance cookies, you must make sure of two things:

- The user agent used to fetch the clearance cookie must match the user agent being used within the requests that use the clearance cookie
> [!NOTE]
> The default user agent used by the scraper is `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36`.
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

    $ pip install -r requirements.txt
    $ python -m patchright install chromium --with-deps


## Usage
> [!NOTE]
> If headless mode isn't working for you, try using headed mode or the [nodriver version](https://github.com/Xewdy444/CF-Clearance-Scraper/tree/nodriver).

> [!WARNING]
> Depending on the user agent used, it may affect your ability to solve the Cloudflare challenge.

```
usage: main.py [-h] [-f FILE] [-t TIMEOUT] [-p PROXY] [-ua USER_AGENT] [--disable-http2] [--disable-http3] [--headed] [-ac] [-c] [-w] [-a] URL

A simple program for scraping Cloudflare clearance (cf_clearance) cookies from websites issuing Cloudflare challenges to visitors

positional arguments:
  URL                   The URL to scrape the Cloudflare clearance cookie from

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The file to write the Cloudflare clearance cookie information to, in JSON format
  -t TIMEOUT, --timeout TIMEOUT
                        The timeout in seconds to use for browser actions and solving challenges
  -p PROXY, --proxy PROXY
                        The proxy server URL to use for the browser requests (SOCKS5 proxy authentication is not supported)
  -ua USER_AGENT, --user-agent USER_AGENT
                        The user agent to use for the browser requests
  --disable-http2       Disable the usage of HTTP/2 for the browser requests
  --disable-http3       Disable the usage of HTTP/3 for the browser requests
  --headed              Run the browser in headed mode
  -ac, --all-cookies    Retrieve all cookies from the page, not just the Cloudflare clearance cookie
  -c, --curl            Get the cURL command for the request with the cookies and user agent
  -w, --wget            Get the Wget command for the request with the cookies and user agent
  -a, --aria2           Get the aria2 command for the request with the cookies and user agent
```

## Example
    $ python main.py --headed -f cookies.json https://sergiodemo.com/security/challenge/legacy-challenge
    [13:27:14] [INFO] Launching headed browser...
    [13:27:14] [INFO] Going to https://sergiodemo.com/security/challenge/legacy-challenge...
    [13:27:15] [INFO] Solving Cloudflare challenge [Interactive]...
    [13:27:18] [INFO] Cookie: cf_clearance=QEAHjebTYeAMsBTeDwsn7aM0sFqMHK5lOsWL9CdZjLk-1736882824-1.2.1.1-FBxJ4RDl.z8ccDWf0.zSVIpk_4bVLINF90adG.Qa8H76Xt1NsgG7cPhNilBinSlkvHMtWM4cpTD1jCsydCIVukmAsouclcKDAz3TAH4UuWUyvXSmnNuBPrFIshz1bByRwfeGjZY45uNV__55S4r4xPldb6yrw0ktCZkKEmfJv64Sw4zbhO3JWsPPIN0yZ3BH2zHKNB6oY_g5KELcFFffMHQcSaZ3yopUQidsdHKP9afDpJC4W5G.7E6B.QVIwW5nj1og9h9h1aP8gTXsEDpJxFNnnBh07n009fDrMxvtFnUcPLYBe6xddAn3WaeeyRH_Zixe7xz1Fd83v1lLBfiZ7g
    [13:27:18] [INFO] User agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
    [13:27:18] [INFO] Writing Cloudflare clearance cookie information to cookies.json...
