from __future__ import annotations

import argparse
import json
import logging
import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from playwright._impl._api_types import Error as PlaywrightError
from playwright.sync_api import sync_playwright

Cookies = List[Dict[str, Any]]


class ChallengePlatform(Enum):
    """Cloudflare challenge platform URI paths."""

    JAVASCRIPT = "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/jsch/v1"
    MANAGED = "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/managed/v1"
    CAPTCHA = "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/captcha/v1"


class CloudflareSolver:
    """
    A class for solving Cloudflare challenges with Playwright.

    Parameters
    ----------
    user_agent : str
        User agent to use for the browser.
    timeout : int
        Request timeout (seconds).
    headless : bool
        Run the browser in headless mode.
    proxy : Optional[str]
        Proxy URL string to use for the browser.

    Attributes
    ----------
    page : playwright.sync_api.Page
        Playwright page object.
    cookies : Cookies
        The cookies from the page.

    Methods
    -------
    solve_challenge()
        Solve the Cloudflare challenge on the current page.
    extract_clearance_cookie(cookies: Cookies) -> Optional[Dict[str, Any]]
        Extract the Cloudflare clearance cookie from a list of cookies.
    detect_challenge() -> Optional[ChallengePlatform]
        Detect the Cloudflare challenge platform on the current page.
    """

    def __init__(
        self,
        *,
        user_agent: str,
        timeout: int,
        headless: bool,
        proxy: Optional[str],
    ) -> None:
        self._playwright = sync_playwright().start()

        if proxy is not None:
            proxy = self._parse_proxy(proxy)

        browser = self._playwright.webkit.launch(headless=headless, proxy=proxy)
        context = browser.new_context(user_agent=user_agent)
        context.set_default_timeout(timeout * 1000)
        self.page = context.new_page()

    def __enter__(self) -> CloudflareSolver:
        return self

    def __exit__(self, *args: Any) -> None:
        self._playwright.stop()

    @staticmethod
    def _parse_proxy(proxy: str) -> Dict[str, str]:
        """
        Parse a proxy URL string into a dictionary of proxy parameters for the Playwright browser.

        Parameters
        ----------
        proxy : str
            Proxy URL string.

        Returns
        -------
        Dict[str, str]
            Dictionary of proxy parameters.
        """
        if "@" in proxy:
            proxy_regex = re.match("(.+)://(.+):(.+)@(.+)", proxy)
            server = f"{proxy_regex.group(1)}://{proxy_regex.group(4)}"

            proxy_params = {
                "server": server,
                "username": proxy_regex.group(2),
                "password": proxy_regex.group(3),
            }
        else:
            proxy_params = {"server": proxy}

        return proxy_params

    def solve_challenge(self) -> None:
        """Solve the Cloudflare challenge on the current page."""
        verify_button_pattern = re.compile(
            "Verify (I am|you are) (not a bot|(a )?human)"
        )

        verify_button = self.page.get_by_role("button", name=verify_button_pattern)
        challenge_spinner = self.page.locator("#challenge-spinner")
        challenge_stage = self.page.locator("div#challenge-stage")

        while (
            self.extract_clearance_cookie(self.cookies) is None
            and self.detect_challenge() is not None
        ):
            if challenge_spinner.is_visible():
                challenge_spinner.wait_for(state="hidden")

            if verify_button.is_visible():
                verify_button.click()
                challenge_stage.wait_for(state="hidden")
            elif any(
                re.match(url, frame.url) is not None
                for url in (
                    "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/[bg]/turnstile",
                    "https://cf-assets.hcaptcha.com/captcha/v1",
                )
                for frame in self.page.frames
            ):
                self.page.reload()

    @property
    def cookies(self) -> Cookies:
        """
        The cookies from the page.

        Returns
        -------
        Cookies
            List of cookies.
        """
        return self.page.context.cookies()

    @staticmethod
    def extract_clearance_cookie(cookies: Cookies) -> Optional[Dict[str, Any]]:
        """
        Extract the Cloudflare clearance cookie from a list of cookies.

        Parameters
        ----------
        cookies : Cookies
            List of cookies.

        Returns
        -------
        Optional[Dict[str, Any]]
            cf_clearance cookie dictionary.
        """
        for cookie in cookies:
            if cookie["name"] == "cf_clearance":
                return cookie

        return None

    def detect_challenge(self) -> Optional[ChallengePlatform]:
        """
        Detect the Cloudflare challenge platform on the current page.

        Returns
        -------
        Optional[ChallengePlatform]
            Cloudflare challenge platform.
        """
        html = self.page.content()

        for platform in ChallengePlatform:
            if re.search(platform.value, html) is not None:
                return platform

        return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A simple program for scraping Cloudflare clearance (cf_clearance) cookies from websites issuing Cloudflare challenges to visitors"
    )
    parser.add_argument(
        "-v", "--verbose", help="Increase output verbosity", action="store_true"
    )
    parser.add_argument(
        "-d", "--debug", help="Run the browser in headed mode", action="store_true"
    )
    parser.add_argument(
        "-u",
        "--url",
        help="URL to fetch the Cloudflare clearance cookie from",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-f",
        "--file",
        help="File to write the Cloudflare clearance cookie information to (JSON format)",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Request timeout (seconds)",
        type=int,
        default=15,
    )
    parser.add_argument(
        "-p",
        "--proxy",
        help="Proxy server to use for requests (SOCKS5 proxy authentication not supported)",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-ua",
        "--user-agent",
        help="User agent to use for requests",
        type=str,
        default="Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko)",
    )

    args = parser.parse_args()
    logging_level = logging.INFO if args.verbose else logging.ERROR

    logging.basicConfig(
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        level=logging_level,
    )

    logging.info("Launching %s browser...", "headed" if args.debug else "headless")

    challenge_messages = {
        ChallengePlatform.JAVASCRIPT: "Solving Cloudflare challenge [JavaScript]...",
        ChallengePlatform.MANAGED: "Solving Cloudflare challenge [Managed]...",
    }

    with CloudflareSolver(
        user_agent=args.user_agent,
        timeout=args.timeout,
        headless=not args.debug,
        proxy=args.proxy,
    ) as solver:
        logging.info("Going to %s...", args.url)

        try:
            solver.page.goto(args.url)
        except PlaywrightError as err:
            logging.error(err)
            return

        challenge_platform = solver.detect_challenge()

        if challenge_platform is None:
            logging.error("No Cloudflare challenge detected.")
            return

        if challenge_platform == ChallengePlatform.CAPTCHA:
            logging.error("Cloudflare returned a CAPTCHA page.")
            return

        logging.info(challenge_messages[challenge_platform])

        try:
            solver.solve_challenge()
        except PlaywrightError as err:
            logging.error(err)

        clearance_cookie = solver.extract_clearance_cookie(solver.cookies)

    if clearance_cookie is None:
        logging.error("Failed to retrieve the Cloudflare clearance cookie.")
        return

    if not args.verbose:
        print(clearance_cookie["value"])

    logging.info("Cookie: cf_clearance=%s", clearance_cookie["value"])
    logging.info("User agent: %s", args.user_agent)

    if args.file is None:
        return

    logging.info("Writing Cloudflare clearance cookie information to %s...", args.file)

    try:
        with open(args.file, encoding="utf-8") as file:
            json_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        json_data = {"clearance_cookies": []}

    # Get the unix timestamp using the cookie's expiration date minus one year
    unix_timestamp = clearance_cookie["expires"] - 31557600
    timestamp = datetime.utcfromtimestamp(unix_timestamp).isoformat()

    json_data["clearance_cookies"].append(
        {
            "unix_timestamp": unix_timestamp,
            "timestamp": timestamp,
            "domain": clearance_cookie["domain"],
            "cf_clearance": clearance_cookie["value"],
            "user_agent": args.user_agent,
            "proxy": args.proxy,
        }
    )

    with open(args.file, "w", encoding="utf-8") as file:
        json.dump(json_data, file, indent=4)


if __name__ == "__main__":
    main()
