from __future__ import annotations

import argparse
import json
import logging
import re
import urllib.parse as urlparse
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from playwright.sync_api import Cookie
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Frame, sync_playwright


class ChallengePlatform(Enum):
    """Cloudflare challenge platform types."""

    JAVASCRIPT = "non-interactive"
    MANAGED = "managed"
    INTERACTIVE = "interactive"


class CloudflareSolver:
    """
    A class for solving Cloudflare challenges with Playwright.

    Parameters
    ----------
    user_agent : str
        The user agent string to use for the browser requests.
    timeout : float
        The timeout in seconds to use for browser actions and solving challenges.
    http2 : bool
        Enable or disable the usage of HTTP/2 for the browser requests.
    http3 : bool
        Enable or disable the usage of HTTP/3 for the browser requests.
    headless : bool
        Enable or disable headless mode for the browser.
    proxy : Optional[str]
        The proxy server URL to use for the browser requests.
    """

    def __init__(
        self,
        *,
        user_agent: str,
        timeout: float,
        http2: bool,
        http3: bool,
        headless: bool,
        proxy: Optional[str],
    ) -> None:
        self._playwright = sync_playwright().start()

        if proxy is not None:
            proxy = self._parse_proxy(proxy)

        browser = self._playwright.firefox.launch(
            firefox_user_prefs={
                "network.http.http2.enabled": http2,
                "network.http.http3.enable": http3,
            },
            headless=headless,
            proxy=proxy,
        )

        context = browser.new_context(user_agent=user_agent)
        context.set_default_timeout(timeout * 1000)

        self.page = context.new_page()
        self._timeout = timeout

    def __enter__(self) -> CloudflareSolver:
        return self

    def __exit__(self, *_: Any) -> None:
        self._playwright.stop()

    @staticmethod
    def _parse_proxy(proxy: str) -> Dict[str, str]:
        """
        Parse a proxy URL string into a dictionary of proxy parameters for
        the Playwright browser.

        Parameters
        ----------
        proxy : str
            Proxy URL string.

        Returns
        -------
        Dict[str, str]
            The dictionary of proxy parameters.
        """
        parsed_proxy = urlparse.urlparse(proxy)
        server = f"{parsed_proxy.scheme}://{parsed_proxy.hostname}"

        if parsed_proxy.port is not None:
            server += f":{parsed_proxy.port}"

        proxy_params = {"server": server}

        if parsed_proxy.username is not None and parsed_proxy.password is not None:
            proxy_params.update(
                {"username": parsed_proxy.username, "password": parsed_proxy.password}
            )

        return proxy_params

    def _get_turnstile_frame(self) -> Optional[Frame]:
        """
        Get the Cloudflare turnstile frame.

        Returns
        -------
        Optional[Frame]
            The Cloudflare turnstile frame.
        """
        return self.page.frame(
            url=re.compile(
                "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/[bg]/turnstile"
            ),
        )

    @property
    def cookies(self) -> List[Cookie]:
        """The cookies from the current page."""
        return self.page.context.cookies()

    @staticmethod
    def extract_clearance_cookie(cookies: Iterable[Cookie]) -> Optional[Cookie]:
        """
        Extract the Cloudflare clearance cookie from a list of cookies.

        Parameters
        ----------
        cookies : Iterable[Cookie]
            List of cookies.

        Returns
        -------
        Optional[Cookie]
            The Cloudflare clearance cookie. Returns None if the cookie is not found.
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
            The Cloudflare challenge platform.
        """
        html = self.page.content()

        for platform in ChallengePlatform:
            if f"cType: '{platform.value}'" in html:
                return platform

        return None

    def solve_challenge(self) -> None:
        """Solve the Cloudflare challenge on the current page."""
        verify_button_pattern = re.compile(
            "Verify (I am|you are) (not a bot|(a )?human)"
        )

        verify_button = self.page.get_by_role("button", name=verify_button_pattern)
        challenge_spinner = self.page.locator("#challenge-spinner")
        challenge_stage = self.page.locator("#challenge-stage")
        start_timestamp = datetime.now()

        while (
            self.extract_clearance_cookie(self.cookies) is None
            and self.detect_challenge() is not None
            and (datetime.now() - start_timestamp).seconds < self._timeout
        ):
            if challenge_spinner.is_visible():
                challenge_spinner.wait_for(state="hidden")

            turnstile_frame = self._get_turnstile_frame()

            if verify_button.is_visible():
                verify_button.click()
                challenge_stage.wait_for(state="hidden")
            elif turnstile_frame is not None:
                turnstile_frame.get_by_role("checkbox").click()
                challenge_stage.wait_for(state="hidden")

            self.page.wait_for_timeout(250)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A simple program for scraping Cloudflare clearance (cf_clearance) cookies from websites issuing Cloudflare challenges to visitors"
    )

    parser.add_argument(
        "url",
        metavar="URL",
        help="The URL to scrape the Cloudflare clearance cookie from",
        type=str,
    )

    parser.add_argument(
        "-f",
        "--file",
        default=None,
        help="The file to write the Cloudflare clearance cookie information to, in JSON format",
        type=str,
    )

    parser.add_argument(
        "-t",
        "--timeout",
        default=30,
        help="The timeout in seconds to use for browser actions and solving challenges",
        type=float,
    )

    parser.add_argument(
        "-p",
        "--proxy",
        default=None,
        help="The proxy server URL to use for the browser requests (SOCKS5 proxy authentication is not supported)",
        type=str,
    )

    parser.add_argument(
        "-ua",
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        help="The user agent to use for the browser requests",
        type=str,
    )

    parser.add_argument(
        "--disable-http2",
        action="store_true",
        help="Disable the usage of HTTP/2 for the browser requests",
    )

    parser.add_argument(
        "--disable-http3",
        action="store_true",
        help="Disable the usage of HTTP/3 for the browser requests",
    )

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Run the browser in headed mode",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Increase the output verbosity",
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
        ChallengePlatform.INTERACTIVE: "Solving Cloudflare challenge [Interactive]...",
    }

    with CloudflareSolver(
        user_agent=args.user_agent,
        timeout=args.timeout,
        http2=not args.disable_http2,
        http3=not args.disable_http3,
        headless=not args.debug,
        proxy=args.proxy,
    ) as solver:
        logging.info("Going to %s...", args.url)

        try:
            solver.page.goto(args.url)
        except PlaywrightError as err:
            logging.error(err)
            return

        clearance_cookie = solver.extract_clearance_cookie(solver.cookies)

        if clearance_cookie is not None:
            logging.info("Cookie: cf_clearance=%s", clearance_cookie["value"])
            logging.info("User agent: %s", args.user_agent)

            if not args.verbose:
                print(f'cf_clearance={clearance_cookie["value"]}')

            return

        challenge_platform = solver.detect_challenge()

        if challenge_platform is None:
            logging.error("No Cloudflare challenge detected.")
            return

        logging.info(challenge_messages[challenge_platform])

        try:
            solver.solve_challenge()
        except PlaywrightError as err:
            logging.error(err)

        clearance_cookie = solver.extract_clearance_cookie(solver.cookies)

    if clearance_cookie is None:
        logging.error("Failed to retrieve a Cloudflare clearance cookie.")
        return

    logging.info("Cookie: cf_clearance=%s", clearance_cookie["value"])
    logging.info("User agent: %s", args.user_agent)

    if not args.verbose:
        print(f'cf_clearance={clearance_cookie["value"]}')

    if args.file is None:
        return

    logging.info("Writing Cloudflare clearance cookie information to %s...", args.file)

    try:
        with open(args.file, encoding="utf-8") as file:
            json_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        json_data = {"clearance_cookies": []}

    local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
    unix_timestamp = clearance_cookie["expires"] - timedelta(days=365).total_seconds()
    timestamp = datetime.fromtimestamp(unix_timestamp, tz=local_timezone).isoformat()

    json_data["clearance_cookies"].append(
        {
            "unix_timestamp": int(unix_timestamp),
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
