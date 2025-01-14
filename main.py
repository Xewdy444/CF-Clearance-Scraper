from __future__ import annotations

import argparse
import json
import logging
import re
import urllib.parse as urlparse
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Final, Iterable, List, Optional

from patchright.sync_api import Cookie
from patchright.sync_api import Error as PlaywrightError
from patchright.sync_api import Frame, sync_playwright

COMMAND: Final[str] = (
    '{name}: {binary} --header "Cookie: {cookies}" --header "User-Agent: {user_agent}" {url}'
)


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
        args: List[str] = []

        if not http2:
            args.append("--disable-http2")

        if not http3:
            args.append("--disable-quic")

        if proxy is not None:
            proxy = self._parse_proxy(proxy)

        browser = self._playwright.chromium.launch(
            args=args, headless=headless, proxy=proxy
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
                self.page.mouse.click(210, 290)
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
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
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
        "--headed",
        action="store_true",
        help="Run the browser in headed mode",
    )

    parser.add_argument(
        "-ac",
        "--all-cookies",
        action="store_true",
        help="Retrieve all cookies from the page, not just the Cloudflare clearance cookie",
    )

    parser.add_argument(
        "-c",
        "--curl",
        action="store_true",
        help="Get the cURL command for the request with the cookies and user agent",
    )

    parser.add_argument(
        "-w",
        "--wget",
        action="store_true",
        help="Get the Wget command for the request with the cookies and user agent",
    )

    parser.add_argument(
        "-a",
        "--aria2",
        action="store_true",
        help="Get the aria2 command for the request with the cookies and user agent",
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        level=logging.INFO,
    )

    logging.info("Launching %s browser...", "headed" if args.headed else "headless")

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
        headless=not args.headed,
        proxy=args.proxy,
    ) as solver:
        logging.info("Going to %s...", args.url)

        try:
            solver.page.goto(args.url)
        except PlaywrightError as err:
            logging.error(err)
            return

        clearance_cookie = solver.extract_clearance_cookie(solver.cookies)

        if clearance_cookie is None:
            challenge_platform = solver.detect_challenge()

            if challenge_platform is None:
                logging.error("No Cloudflare challenge detected.")
                return

            logging.info(challenge_messages[challenge_platform])

            try:
                solver.solve_challenge()
            except PlaywrightError as err:
                logging.error(err)

            all_cookies = solver.cookies
            clearance_cookie = solver.extract_clearance_cookie(all_cookies)

    if clearance_cookie is None:
        logging.error("Failed to retrieve a Cloudflare clearance cookie.")
        return

    cookie_string = "; ".join(
        f'{cookie["name"]}={cookie["value"]}' for cookie in all_cookies
    )

    if args.all_cookies:
        logging.info("All cookies: %s", cookie_string)
    else:
        logging.info("Cookie: cf_clearance=%s", clearance_cookie["value"])

    logging.info("User agent: %s", args.user_agent)

    if args.curl:
        logging.info(
            COMMAND.format(
                name="cURL",
                binary="curl",
                cookies=(
                    cookie_string
                    if args.all_cookies
                    else f'cf_clearance={clearance_cookie["value"]}'
                ),
                user_agent=args.user_agent,
                url=(
                    f"--proxy {args.proxy} {args.url}"
                    if args.proxy is not None
                    else args.url
                ),
            )
        )

    if args.wget:
        if args.proxy is not None:
            logging.warning(
                "Proxies must be set in an environment variable or config file for Wget."
            )

        logging.info(
            COMMAND.format(
                name="Wget",
                binary="wget",
                cookies=(
                    cookie_string
                    if args.all_cookies
                    else f'cf_clearance={clearance_cookie["value"]}'
                ),
                user_agent=args.user_agent,
                url=args.url,
            )
        )

    if args.aria2:
        if args.proxy is not None and args.proxy.casefold().startswith("socks"):
            logging.warning("SOCKS proxies are not supported by aria2.")

        logging.info(
            COMMAND.format(
                name="aria2",
                binary="aria2c",
                cookies=(
                    cookie_string
                    if args.all_cookies
                    else f'cf_clearance={clearance_cookie["value"]}'
                ),
                user_agent=args.user_agent,
                url=(
                    f"--all-proxy {args.proxy} {args.url}"
                    if args.proxy is not None
                    else args.url
                ),
            )
        )

    if args.file is None:
        return

    logging.info("Writing Cloudflare clearance cookie information to %s...", args.file)

    try:
        with open(args.file, encoding="utf-8") as file:
            json_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        json_data: Dict[str, List[Dict[str, Any]]] = {}

    local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
    unix_timestamp = clearance_cookie["expires"] - timedelta(days=365).total_seconds()
    timestamp = datetime.fromtimestamp(unix_timestamp, tz=local_timezone).isoformat()

    json_data.setdefault(clearance_cookie["domain"], []).append(
        {
            "unix_timestamp": int(unix_timestamp),
            "timestamp": timestamp,
            "cf_clearance": clearance_cookie["value"],
            "cookies": all_cookies,
            "user_agent": args.user_agent,
            "proxy": args.proxy,
        }
    )

    with open(args.file, "w", encoding="utf-8") as file:
        json.dump(json_data, file, indent=4)


if __name__ == "__main__":
    main()
