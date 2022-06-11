import argparse
import asyncio
import sys
from os import path

import requests
from playwright.async_api import async_playwright


async def main():
    # Edit the user agent to match the user agent being used within the requests that use the clearance cookie
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15"

    parser = argparse.ArgumentParser(
        description="Fetches cf_clearance cookies from websites issuing cloudflare challenges to users"
    )
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose logging", action="store_true"
    )
    parser.add_argument(
        "-u",
        "--url",
        help="URL to fetch cf_clearance cookie from",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="File to write the cf_clearance cookie value to",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Cookie fetch timeout (milliseconds)",
        type=int,
        default=5000,
    )
    parser.add_argument(
        "-p",
        "--proxy",
        help="Proxy server to use for requests (Authentification not supported). Example: socks5://172.66.43.144:1080",
        type=str,
        default=None,
    )
    args = parser.parse_args()

    if args.url is None:
        sys.exit(parser.print_help())

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-us",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": user_agent,
    }

    try:
        if args.proxy:
            proxy = {"http": args.proxy, "https": args.proxy}
            init_request = requests.get(args.url, headers=headers, proxies=proxy)
        else:
            init_request = requests.get(args.url, headers=headers)
    except Exception as e:
        if args.verbose is True:
            sys.exit(f"[!] {e}")

    cf_challenge_html = [
        "<title>Please Wait... | Cloudflare</title>",
        "<title>Attention Required! | Cloudflare</title>",
        "Checking your browser before accessing",
    ]

    if any(x in init_request.text for x in cf_challenge_html):
        if args.verbose is True:
            print(
                "[+] Cloudflare challenge detected. Attempting to fetch cf_clearance cookie..."
            )
    else:
        if args.verbose is True:
            sys.exit("[!] Cloudflare challenge not detected. Exiting...")

    async with async_playwright() as p:
        if args.verbose is True:
            print("[+] Launching headless browser...")

        if args.proxy:
            browser = await p.webkit.launch(headless=True, proxy={"server": args.proxy})
        else:
            browser = await p.webkit.launch(headless=True)

        try:
            context = await browser.new_context(user_agent=user_agent)
            page = await context.new_page()
            await page.goto(args.url, wait_until="networkidle")
            await page.wait_for_timeout(args.timeout)
        except Exception as e:
            if args.verbose is True:
                print("[!] {}".format(str(e).split("\n")[0]))
                print("[+] Closing headless browser...")
            await browser.close()
            sys.exit()

        cookies = await page.context.cookies()
        cf_clearance_cookie = [
            cookie for cookie in cookies if cookie["name"] == "cf_clearance"
        ]

        if len(cf_clearance_cookie) != 0:
            if args.verbose is True:
                print(f"[+] Cookie: cf_clearance={cf_clearance_cookie[0]['value']}")
            elif args.verbose is False:
                print(cf_clearance_cookie[0]["value"])

            if args.file:
                try:
                    if path.exists(args.file):
                        with open(args.file, "a") as file:
                            if args.verbose is True:
                                print(
                                    f"[+] Writing cf_clearance cookie value to {args.file}..."
                                )
                            file.write(cf_clearance_cookie[0]["value"] + "\n")
                    else:
                        with open(args.file, "w") as file:
                            if args.verbose is True:
                                print(
                                    f"[+] Writing cf_clearance cookie value to {args.file}..."
                                )
                            file.write(cf_clearance_cookie[0]["value"] + "\n")
                except Exception as e:
                    print(f"[!] {e}")
        else:
            if args.verbose is True:
                print("[!] Failed to retrieve cf_clearance cookie.")

        if args.verbose is True:
            print("[+] Closing headless browser...")
        await browser.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit()
