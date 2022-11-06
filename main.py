import argparse
import logging
import re
import sys
from typing import Any, Dict, List

import httpx
from playwright._impl._api_types import Error as PlaywrightError
from playwright.sync_api import Page, sync_playwright
from tenacity import retry, retry_if_exception_type

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko)"
)


def detect_challenge(html: str) -> bool:
    challenge_html = (
        "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/managed/v1",
        "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/jsch/v1",
    )

    return any(re.search(x, html) for x in challenge_html)


def parse_proxy(proxy: str) -> Dict[str, str]:
    if "@" in proxy:
        proxy_regex = re.match("(.+)://(.+):(.+)@(.+)", proxy)
        server = f"{proxy_regex.group(1)}://{proxy_regex.group(4)}"

        proxy_dict = {
            "server": server,
            "username": proxy_regex.group(2),
            "password": proxy_regex.group(3),
        }
    else:
        proxy_dict = {"server": proxy}

    return proxy_dict


@retry(retry=retry_if_exception_type(PlaywrightError))
def ensure_html(page: Page) -> str:
    return page.content()


def solve_challenge(page: Page) -> None:
    verify_button = page.locator("text=/Verify (I am|you are) (not a bot|(a )?human)/")
    spinner = page.locator("#challenge-spinner")

    while detect_challenge(ensure_html(page)):
        if spinner.is_visible():
            spinner.wait_for(state="hidden")

        challenge_stage = page.query_selector("div#challenge-stage")
        captcha_box = page.query_selector("div.hcaptcha-box")

        if verify_button.is_visible():
            verify_button.click()
            challenge_stage.wait_for_element_state("hidden")
        elif captcha_box is not None:
            page.reload()


def get_cookies(args: argparse.Namespace) -> List[Dict[str, Any]]:
    with sync_playwright() as playwright:
        logging.info("Launching headless browser...")

        if args.proxy is not None:
            browser = playwright.webkit.launch(
                headless=True, proxy=parse_proxy(args.proxy)
            )
        else:
            browser = playwright.webkit.launch(headless=True)

        ms_timeout = args.timeout * 1000
        context = browser.new_context(user_agent=USER_AGENT)
        context.set_default_timeout(ms_timeout)
        page = context.new_page()

        logging.info("Going to %s...", args.url)

        try:
            page.goto(args.url)
        except PlaywrightError as err:
            sys.exit(logging.info(err.message))

        if re.search(
            "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/managed/v1",
            page.content(),
        ):
            logging.info("Solving cloudflare challenge [Managed]...")
        elif re.search(
            "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/jsch/v1", page.content()
        ):
            logging.info("Solving cloudflare challenge [JavaScript]...")

        try:
            solve_challenge(page)
        except PlaywrightError:
            pass

        return context.cookies()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetches cf_clearance cookies from websites issuing cloudflare challenges to users"
    )
    parser.add_argument(
        "-v", "--verbose", help="Increase output verbosity", action="store_true"
    )
    parser.add_argument(
        "-u",
        "--url",
        help="URL to fetch cf_clearance cookie from",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="File to write the cf_clearance cookie to",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Request timeout (seconds)",
        type=int,
        default=5,
    )
    parser.add_argument(
        "-p",
        "--proxy",
        help="Proxy server to use for requests (SOCKS5 proxy authentication not supported). Example: socks5://172.66.43.144:1080 or http://username:password@172.66.43.144:1080",
        type=str,
        default=None,
    )
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            format="[%(asctime)s] %(message)s",
            datefmt="%H:%M:%S",
            level=logging.INFO,
        )

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": USER_AGENT,
    }

    logging.info("Checking for cloudflare challenge...")

    try:
        with httpx.Client(
            http2=True,
            follow_redirects=True,
            headers=headers,
            timeout=args.timeout,
            proxies=args.proxy,
        ) as client:
            probe_request = client.get(args.url)
    except httpx.HTTPError as err:
        sys.exit(logging.info(err))

    if re.search(
        "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/captcha/v1", probe_request.text
    ):
        sys.exit(logging.info("Cloudflare returned an hCaptcha page."))

    if detect_challenge(probe_request.text):
        logging.info("Cloudflare challenge detected. Fetching cf_clearance cookie...")
    else:
        sys.exit(logging.info("Cloudflare challenge not detected."))

    cookies = get_cookies(args)

    cookie_value = "".join(
        cookie["value"] for cookie in cookies if cookie["name"] == "cf_clearance"
    )

    if not cookie_value:
        sys.exit(logging.info("Failed to retrieve cf_clearance cookie."))

    cookie = f"cf_clearance={cookie_value}"
    logging.info("Cookie: %s", cookie)

    if not args.verbose:
        print(cookie)

    if args.file is not None:
        logging.info("Writing cf_clearance cookie to %s...", args.file)

        with open(args.file, "a", encoding="utf-8") as file:
            file.write(f"{cookie}\n")


if __name__ == "__main__":
    main()
