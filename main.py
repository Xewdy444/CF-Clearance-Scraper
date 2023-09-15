from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

import selenium.webdriver.support.expected_conditions as EC
import seleniumwire.undetected_chromedriver as chromedriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait

Cookie = Dict[str, Any]


class ChallengeElements(Enum):
    """Cloudflare challenge elements."""

    CHALLENGE_STAGE = (By.CSS_SELECTOR, "#challenge-stage")
    CHALLENGE_SPINNER = (By.CSS_SELECTOR, "#challenge-spinner")
    TURNSTILE_FRAME = (
        By.XPATH,
        '//iframe[@title="Widget containing a Cloudflare security challenge"]',
    )
    TURNSTILE_CHECKBOX = (
        By.CSS_SELECTOR,
        "#challenge-stage > div > label > input[type=checkbox]",
    )
    TURNSTILE_TEXT = (
        By.CSS_SELECTOR,
        "#challenge-stage > div > label > span.ctp-label",
    )
    VERIFY_BUTTON = (
        By.XPATH,
        '//input[@type="button" and contains(text(), "Verify (I am|you are) (not a bot|(a )?human)")]',
    )


class ChallengePlatform(Enum):
    """Cloudflare challenge platform types."""

    JAVASCRIPT = "non-interactive"
    MANAGED = "managed"
    INTERACTIVE = "interactive"


class CloudflareSolver:
    """
    A class for solving Cloudflare challenges with undetected-chromedriver.

    Parameters
    ----------
    user_agent : str
        The user agent string to use for the browser requests.
    timeout : float
        The timeout in seconds to use for browser actions and solving challenges.
    http2 : bool
        Enable or disable the usage of HTTP/2 for the browser requests.
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
        headless: bool,
        proxy: Optional[str],
    ) -> None:
        options = chromedriver.ChromeOptions()
        options.add_argument(f"--user-agent={user_agent}")

        if not http2:
            options.add_argument("--disable-http2")

        seleniumwire_options = {"disable_capture": True}

        if proxy is not None:
            seleniumwire_options["proxy"] = {"http": proxy, "https": proxy}

        self.driver = chromedriver.Chrome(
            seleniumwire_options=seleniumwire_options,
            options=options,
            headless=headless,
        )

        self.driver.set_page_load_timeout(timeout)
        self._timeout = timeout

    def __enter__(self) -> CloudflareSolver:
        return self

    def __exit__(self, *args: Any) -> None:
        self.driver.quit()

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

        while (
            self.driver.get_cookie("cf_clearance") is None
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

            verify_button = self.driver.find_elements(
                *ChallengeElements.VERIFY_BUTTON.value
            )

            turnstile_frame = self.driver.find_element(
                *ChallengeElements.TURNSTILE_FRAME.value
            )

            if verify_button:
                verify_button[0].click()

                WebDriverWait(self.driver, self._timeout).until(
                    EC.invisibility_of_element_located(
                        ChallengeElements.CHALLENGE_STAGE.value
                    )
                )
            elif turnstile_frame.is_displayed():
                self.driver.switch_to.frame(turnstile_frame)

                WebDriverWait(self.driver, self._timeout).until(
                    EC.text_to_be_present_in_element(
                        ChallengeElements.TURNSTILE_TEXT.value, "Verify you are human"
                    )
                )

                checkbox = self.driver.find_element(
                    *ChallengeElements.TURNSTILE_CHECKBOX.value
                )

                checkbox.click()
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
        help="The timeout in seconds to use for browser actions and solving challenges",
        type=float,
    )

    parser.add_argument(
        "-p",
        "--proxy",
        default=None,
        help="The proxy server URL to use for the browser requests",
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
        "--disable-http2",
        action="store_true",
        help="Disable the usage of HTTP/2 for the browser requests",
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

    logging.getLogger("seleniumwire").setLevel(logging.WARNING)
    logging.getLogger("undetected_chromedriver").setLevel(logging.WARNING)
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

        clearance_cookie = solver.driver.get_cookie("cf_clearance")

    if clearance_cookie is None:
        logging.error("Failed to retrieve a Cloudflare clearance cookie.")
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
    unix_timestamp = clearance_cookie["expiry"] - 31557600
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
