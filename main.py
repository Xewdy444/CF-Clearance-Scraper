from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

import selenium.webdriver.support.expected_conditions as EC
import undetected_chromedriver as chromedriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.wait import WebDriverWait
from undetected_chromedriver import By

Cookie = Dict[str, Any]


class ChallengeElements(Enum):
    """Cloudflare challenge elements."""

    CHALLENGE_STAGE = (By.CSS_SELECTOR, "#challenge-stage")
    CHALLENGE_SPINNER = (By.CSS_SELECTOR, "#challenge-spinner")
    TURNSTILE_CHECKBOX = (By.CSS_SELECTOR, "#challenge-stage > div > label > map > img")


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
        The action/solve timeout in seconds.
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
        headless: bool,
        proxy: Optional[str],
    ) -> None:
        options = chromedriver.ChromeOptions()
        options.add_argument(f"--user-agent={user_agent}")

        if proxy is not None:
            options.add_argument(f"--proxy-server={proxy}")

        self.driver = chromedriver.Chrome(options=options, headless=headless)
        self.driver.set_page_load_timeout(timeout)
        self._timeout = timeout

    def __enter__(self) -> CloudflareSolver:
        return self

    def __exit__(self, *args: Any) -> None:
        try:
            self.driver.quit()
        except OSError:
            pass

    @property
    def cookies(self) -> List[Cookie]:
        """The cookies from the current session."""
        return self.driver.get_cookies()

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
        html = self.driver.page_source

        for platform in ChallengePlatform:
            if f"cType: '{platform.value}'" in html:
                return platform

        return None

    def solve_challenge(self) -> None:
        """Solve the Cloudflare challenge on the current page."""
        start_timestamp = datetime.now()

        # TODO: Add check for simple button challenge

        while (
            self.extract_clearance_cookie(self.cookies) is None
            and self.detect_challenge() is not None
            and (datetime.now() - start_timestamp).seconds < self._timeout
        ):
            challenge_spinner = self.driver.find_element(
                *ChallengeElements.CHALLENGE_SPINNER.value
            )

            if challenge_spinner.is_displayed():
                WebDriverWait(self.driver, self._timeout).until(
                    EC.invisibility_of_element_located(
                        ChallengeElements.CHALLENGE_SPINNER.value
                    )
                )

            turnstile_frame = self.driver.find_element(
                By.XPATH,
                '//*[@title="Widget containing a Cloudflare security challenge"]',
            )

            if turnstile_frame.is_displayed():
                self.driver.switch_to.frame(turnstile_frame)

                WebDriverWait(self.driver, self._timeout).until(
                    EC.visibility_of_element_located(
                        ChallengeElements.TURNSTILE_CHECKBOX.value
                    )
                )

                checkbox = self.driver.find_element(
                    *ChallengeElements.TURNSTILE_CHECKBOX.value
                )

                actions = ActionChains(self.driver)
                actions.move_to_element_with_offset(checkbox, 5, 7)
                actions.click(checkbox)
                actions.perform()

                self.driver.switch_to.default_content()

                WebDriverWait(self.driver, self._timeout).until(
                    EC.invisibility_of_element_located(
                        ChallengeElements.CHALLENGE_STAGE.value
                    )
                )

            self.driver.implicitly_wait(0.25)


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
        help="The action/solve timeout in seconds.",
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
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        help="The user agent to use for the browser requests",
        type=str,
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
        headless=not args.debug,
        proxy=args.proxy,
    ) as solver:
        logging.info("Going to %s...", args.url)

        try:
            solver.driver.get(args.url)
        except TimeoutException as err:
            logging.error(err)
            return

        challenge_platform = solver.detect_challenge()

        if challenge_platform is None:
            logging.error("No Cloudflare challenge detected.")
            return

        logging.info(challenge_messages[challenge_platform])

        try:
            solver.solve_challenge()
        except TimeoutException:
            pass

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
