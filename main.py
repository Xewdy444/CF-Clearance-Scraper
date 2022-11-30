from __future__ import annotations

import argparse
import logging
import re
import sys
from typing import Any, Dict, List, Optional

from playwright._impl._api_types import Error as PlaywrightError
from playwright.sync_api import sync_playwright


class Scraper:
    """
    Cookie scraper class.

    Parameters
    ----------
    user_agent : str
        User agent to use for requests.
    timeout : int
        Timeout in seconds.
    debug : bool
        Whether to run the browser in headed mode.
    proxy : Optional[str]
        Proxy to use for requests.

    Methods
    -------
    parse_clearance_cookie(cookies: List[Dict[str, Any]]) -> Optional[str]
        Parse the cf_clearance cookie from a list of cookies.
    get_cookies(self, url: str) -> Optional[List[Dict[str, Any]]]
        Solve the cloudflare challenge and get cookies from the page.
    """

    def __init__(
        self,
        *,
        user_agent: str,
        timeout: int,
        debug: bool,
        proxy: Optional[str],
    ) -> None:
        self._playwright = sync_playwright().start()

        if proxy is None:
            browser = self._playwright.webkit.launch(headless=not debug)
        else:
            browser = self._playwright.webkit.launch(
                headless=not debug, proxy=self._parse_proxy(proxy)
            )

        context = browser.new_context(user_agent=user_agent)
        context.set_default_timeout(timeout * 1000)
        self._page = context.new_page()

    def __enter__(self) -> Scraper:
        return self

    def __exit__(self, *args: Any) -> None:
        self._playwright.stop()

    def _parse_proxy(self, proxy: str) -> Dict[str, str]:
        """
        Parse proxy string into a dictionary.

        Parameters
        ----------
        proxy : str
            Proxy string.

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

    def _detect_challenge(self) -> bool:
        """
        Detect if the page is a cloudflare challenge.

        Parameters
        ----------
        html : str
            HTML of the page.

        Returns
        -------
        bool
            True if the page is a cloudflare challenge, False otherwise.
        """
        challenge_uri_paths = (
            "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/managed/v1",
            "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/jsch/v1",
        )

        return any(
            re.search(uri_path, self._page.content())
            for uri_path in challenge_uri_paths
        )

    def _solve_challenge(self) -> None:
        """Solve the cloudflare challenge."""
        verify_button_pattern = re.compile(
            "Verify (I am|you are) (not a bot|(a )?human)"
        )

        verify_button = self._page.get_by_role("button", name=verify_button_pattern)
        spinner = self._page.locator("#challenge-spinner")

        while self._detect_challenge():
            if spinner.is_visible():
                spinner.wait_for(state="hidden")

            challenge_stage = self._page.query_selector("div#challenge-stage")

            if verify_button.is_visible():
                verify_button.click()
                challenge_stage.wait_for_element_state("hidden")
            elif any(
                re.match(uri_path, frame.url)
                for uri_path in (
                    "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/[bg]/turnstile",
                    "https://cf-assets.hcaptcha.com/captcha/v1",
                )
                for frame in self._page.frames
            ):
                self._page.reload()

    @staticmethod
    def parse_clearance_cookie(cookies: List[Dict[str, Any]]) -> Optional[str]:
        """
        Parse the cf_clearance cookie from a list of cookies.

        Parameters
        ----------
        cookies : List[Dict[str, Any]]
            List of cookies.

        Returns
        -------
        Optional[str]
            cf_clearance cookie.
        """
        cookie_value = "".join(
            cookie["value"] for cookie in cookies if cookie["name"] == "cf_clearance"
        )

        if not cookie_value:
            return None

        return f"cf_clearance={cookie_value}"

    def get_cookies(self, url: str) -> Optional[List[Dict[str, Any]]]:
        """
        Solve the cloudflare challenge and get cookies from the page.

        Parameters
        ----------
        url : str
            URL to scrape cookies from.

        Returns
        -------
        Optional[List[Dict[str, Any]]]
            List of cookies.
        """
        try:
            self._page.goto(url)
        except PlaywrightError as err:
            logging.error(err)
            return None

        html = self._page.content()

        if re.search("/cdn-cgi/challenge-platform/h/[bg]/orchestrate/jsch/v1", html):
            logging.info("Solving cloudflare challenge [JavaScript]...")
        elif re.search(
            "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/managed/v1", html
        ):
            logging.info("Solving cloudflare challenge [Managed]...")
        elif re.search(
            "/cdn-cgi/challenge-platform/h/[bg]/orchestrate/captcha/v1", html
        ):
            logging.error("Cloudflare returned an hCaptcha page.")
            return None
        else:
            logging.error("No cloudflare challenge detected.")
            return None

        try:
            self._solve_challenge()
        except PlaywrightError:
            pass

        return self._page.context.cookies()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetches cf_clearance cookies from websites issuing cloudflare challenges to users"
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
        help="URL to fetch cf_clearance cookie from",
        type=str,
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

    if args.verbose:
        logging.basicConfig(
            format="[%(asctime)s] %(message)s",
            datefmt="%H:%M:%S",
            level=logging.INFO,
        )

    logging.info("Launching %s browser...", "headless" if not args.debug else "headed")

    with Scraper(
        user_agent=args.user_agent,
        timeout=args.timeout,
        debug=args.debug,
        proxy=args.proxy,
    ) as scraper:
        logging.info("Going to %s...", args.url)
        cookies = scraper.get_cookies(args.url)

        if cookies is None:
            sys.exit(1)

        clearance_cookie = scraper.parse_clearance_cookie(cookies)

    if not clearance_cookie:
        logging.error("Failed to retrieve cf_clearance cookie.")
        sys.exit(1)

    logging.info("Cookie: %s", clearance_cookie)

    if not args.verbose:
        print(clearance_cookie)

    if args.file is not None:
        logging.info("Writing cf_clearance cookie to %s...", args.file)

        with open(args.file, "a", encoding="utf-8") as file:
            file.write(f"{clearance_cookie}\n")


if __name__ == "__main__":
    main()
