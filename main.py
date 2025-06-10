import argparse
import asyncio
import aiohttp
import logging
import os
import sys
from typing import List, Optional
from tqdm import tqdm

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BreachAlarm:
    """
    A class for checking email addresses against the Have I Been Pwned API and searching public code repositories
    and paste sites for leaked credentials.
    """

    def __init__(self, email: Optional[str] = None, org_name: Optional[str] = None, technology: Optional[str] = None):
        """
        Initializes the BreachAlarm class.

        Args:
            email (Optional[str]): The email address to check against the Have I Been Pwned API. Defaults to None.
            org_name (Optional[str]): The organization name to search for in public code repositories and paste sites. Defaults to None.
            technology (Optional[str]): The technology to search for in public code repositories and paste sites. Defaults to None.
        """
        self.email = email
        self.org_name = org_name
        self.technology = technology

    async def check_hibp(self, email: str) -> Optional[List[str]]:
        """
        Checks an email address against the Have I Been Pwned API.

        Args:
            email (str): The email address to check.

        Returns:
            Optional[List[str]]: A list of breach names if the email address has been involved in any known data breaches, otherwise None.
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                headers = {'hibp-api-key': 'anonymous'}  # Replace with your HIBP API key if you have one
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        breach_names = [breach['Name'] for breach in data]
                        logging.info(f"Email {email} found in breaches: {breach_names}")
                        return breach_names
                    elif response.status == 404:
                        logging.info(f"Email {email} not found in any breaches.")
                        return None
                    elif response.status == 429:
                         logging.warning("Rate limit exceeded. Please wait and try again later.")
                         print("Rate limit exceeded. Please wait and try again later.")
                         return None
                    else:
                        logging.error(f"Error checking HIBP: Status code {response.status}")
                        print(f"Error checking HIBP: Status code {response.status}")
                        return None
        except aiohttp.ClientError as e:
            logging.error(f"AIOHTTP error: {e}")
            print(f"AIOHTTP error: {e}")
            return None
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            print(f"An unexpected error occurred: {e}")
            return None

    async def search_code_repositories(self, search_term: str) -> None:
        """
        Searches public code repositories for leaked credentials and sensitive information.

        Args:
            search_term (str): The search term to use.
        """
        # Placeholder for code repository searching functionality (e.g., using GitHub API)
        logging.info(f"Searching code repositories for: {search_term}")
        print(f"Searching code repositories for: {search_term} (This feature is a placeholder and does not perform actual searching.)")

    async def search_paste_sites(self, search_term: str) -> None:
        """
        Searches paste sites for leaked credentials and sensitive information.

        Args:
            search_term (str): The search term to use.
        """
        # Placeholder for paste site searching functionality (e.g., using Pastebin API)
        logging.info(f"Searching paste sites for: {search_term}")
        print(f"Searching paste sites for: {search_term} (This feature is a placeholder and does not perform actual searching.)")

    async def run(self) -> None:
        """
        Runs the BreachAlarm tool.
        """
        if self.email:
            logging.info(f"Checking email: {self.email}")
            await self.check_hibp(self.email)
        elif self.org_name:
            logging.info(f"Searching for organization name: {self.org_name}")
            await self.search_code_repositories(self.org_name)
            await self.search_paste_sites(self.org_name)
        elif self.technology:
            logging.info(f"Searching for technology: {self.technology}")
            await self.search_code_repositories(self.technology)
            await self.search_paste_sites(self.technology)
        else:
            print("Please provide an email address, organization name, or technology to search for.")
            logging.warning("No search term provided.")


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Check for leaked credentials and sensitive information.")
    group = parser.add_mutually_exclusive_group(required=True)  # Ensure only one of the options is provided
    group.add_argument("-e", "--email", help="Email address to check against Have I Been Pwned.")
    group.add_argument("-o", "--org", dest="org_name", help="Organization name to search for.")
    group.add_argument("-t", "--tech", dest="technology", help="Technology to search for.")

    return parser


async def main() -> None:
    """
    Main function to run the BreachAlarm tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.email:
        if not is_valid_email(args.email):
           print("Invalid email address format.")
           sys.exit(1)

        breach_alarm = BreachAlarm(email=args.email)
        await breach_alarm.run()
    elif args.org_name:
        if not args.org_name.strip():
            print("Organization name cannot be empty.")
            sys.exit(1)

        breach_alarm = BreachAlarm(org_name=args.org_name)
        await breach_alarm.run()
    elif args.technology:
        if not args.technology.strip():
            print("Technology name cannot be empty.")
            sys.exit(1)
        breach_alarm = BreachAlarm(technology=args.technology)
        await breach_alarm.run()

def is_valid_email(email: str) -> bool:
    """
    Validates the email address format.

    Args:
        email (str): The email address to validate.

    Returns:
        bool: True if the email address is valid, False otherwise.
    """
    import re
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

# Usage Examples:
# 1. Check an email address: python main.py -e test@example.com
# 2. Search for an organization name: python main.py -o ExampleOrg
# 3. Search for a technology: python main.py -t Python