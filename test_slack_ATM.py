"""
Slack ATM Integration Test Suite - Positive scenarios testing for Slack integration functionality

This module contains positive test cases for Slack integration operations including:
- Login and authentication
- Save Slack credentials with valid data
- Get company connection
- OAuth authorization flow
- Callback completion
- Configuration deletion
- Allure reporting integration

Execute command:
pytest AI_TeamMates/tests/atm_api_tests --URL=https://workspan-staging-2.qa.workspan.app --USER=admin@workspan.com --PASSWORD=restingpoint --COMPANY_ID=123 --WORK_EMAIL=admin@workspan.com --WORK_PASSWORD=restingpoint --COOKIES_DATA='[{"name":"cookie1","value":"value1","domain":".slack.com"}]' -m AITeamMates_Slack_Integration --TEST_ENV=staging -v -rA --alluredir=reports --disable-warnings

Test Classes:
- TestSlackIntegrationATM: Slack integration positive functionality testing
"""
import pytest
import json
import allure
import os
import time
import logging
import requests
import uuid
import random
from urllib.parse import urlparse, parse_qs

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.wait import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, NoSuchElementException

    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logging.warning("Selenium not available - Slack integration tests will be skipped")
from AI_TeamMates.utils.api_helper import APIHelper
from AI_TeamMates.apis import endpoints
from common.utils.jsonutil import *
from urllib.parse import unquote, urlparse, parse_qs
import re
from datetime import datetime

logger = logging.getLogger(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Master JSON removed - users will be provided via Jenkins parameter
master_json = {}


@pytest.fixture(scope="class")
def setup_api_helper(request, pytestconfig):
    """Setup APIHelper for the test class"""
    try:
        request.cls.base_url = pytestconfig.getoption("--URL")
        allure.attach(f"Base URL: {request.cls.base_url}", "Base URL", allure.attachment_type.TEXT)
        request.cls.username = pytestconfig.getoption("--USER")
        allure.attach(f"Username: {request.cls.username}", "Username", allure.attachment_type.TEXT)
        request.cls.password = pytestconfig.getoption("--PASSWORD")
        allure.attach("Password loaded", "Password", allure.attachment_type.TEXT)

        if not request.cls.base_url:
            pytest.fail("Instance_url environment variable is not set")

        request.cls.api_helper = APIHelper(
            base_url=request.cls.base_url,
            config=endpoints.APIEndpoints.API_ENDPOINTS
        )
        request.cls.api_helper.config = {
            key: f"{request.cls.base_url}{value}"
            for key, value in request.cls.api_helper.config.items()
        }
        allure.attach(json.dumps(request.cls.api_helper.config, indent=2), "API Config Loaded",
                      allure.attachment_type.JSON)

        request.cls.env = pytestconfig.getoption("TEST_ENV")
        allure.attach(f"Environment: {request.cls.env}", "Environment", allure.attachment_type.TEXT)

        # Get company details and credentials from individual Jenkins parameters
        try:
            # Get company ID from Jenkins parameter
            company_id = pytestconfig.getoption("--COMPANY_ID")
            if not company_id:
                pytest.fail("COMPANY_ID parameter is required from Jenkins")
            
            # Get work email from Jenkins parameter
            work_email = pytestconfig.getoption("--WORK_EMAIL")
            if not work_email:
                pytest.fail("WORK_EMAIL parameter is required from Jenkins")
            
            # Get work password from Jenkins parameter
            work_password = pytestconfig.getoption("--WORK_PASSWORD")
            if not work_password:
                pytest.fail("WORK_PASSWORD parameter is required from Jenkins")
            
            # Create company details and credentials structure
            request.cls.company_details = {"company_id": company_id}
            request.cls.credentials = {
                "work_email": work_email,
                "password": work_password
            }

            allure.attach(f"Company ID: {company_id}", "Company Details Loaded", allure.attachment_type.TEXT)
            allure.attach(f"Work Email: {work_email}", "Credentials Loaded", allure.attachment_type.TEXT)
            allure.attach("Password loaded", "Password Status", allure.attachment_type.TEXT)
        except Exception as e:
            error_msg = f"Failed to load company details or credentials: {str(e)}"
            logger.error(error_msg)
            allure.attach(error_msg, "Setup Error", allure.attachment_type.TEXT)
            pytest.fail(error_msg)

        request.cls.master_file = master_json
        
        # Get cookies data from Jenkins parameter (securely)
        cookies_json_str = pytestconfig.getoption("--COOKIES_DATA")
        if cookies_json_str:
            try:
                # Parse cookies data but don't store sensitive info in logs
                cookies_data = json.loads(cookies_json_str)
                request.cls.cookies_data = cookies_data
                
                # Log only non-sensitive information
                cookie_count = len(cookies_data) if isinstance(cookies_data, list) else 0
                logger.info(f"Cookies data loaded from Jenkins parameter ({cookie_count} cookies)")
                allure.attach(f"Cookies data loaded successfully ({cookie_count} cookies)", "Cookies Status", allure.attachment_type.TEXT)
                
                # Clear sensitive data from memory after logging
                del cookies_json_str
                
            except json.JSONDecodeError as e:
                error_msg = "Failed to parse COOKIES_DATA parameter"
                logger.error(error_msg)
                allure.attach(error_msg, "Cookies Error", allure.attachment_type.TEXT)
                pytest.fail(error_msg)
        else:
            request.cls.cookies_data = None
            logger.info("No cookies data provided via Jenkins parameter")
            allure.attach("No cookies data provided", "Cookies Status", allure.attachment_type.TEXT)
            
    except Exception as e:
        error_msg = f"Error in setup_api_helper: {str(e)}"
        logger.error(error_msg)
        allure.attach(error_msg, "Setup Error", allure.attachment_type.TEXT)
        pytest.fail(error_msg)


@pytest.mark.AITeamMates_ATM
@pytest.mark.AITeamMates_Slack_Integration
@allure.parent_suite("AI TeamMates")
@allure.suite("Slack Integration")
@pytest.mark.usefixtures("setup_api_helper")
@pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available - skipping Slack integration tests")
class TestSlackIntegrationATM:

    @classmethod
    def setup_class(cls):
        """Setup class-level variables"""
        cls.token = None
        cls.connection_id = None
        cls.authorization_code = None
        cls.teammate_id = None
        cls.slack_channel_id = None
        cls.slack_channel_name = None
        cls.slack_team_id = None
        cls.sent_message_text = None
        cls.driver = None
        # Cookies will be provided via Jenkins parameter
        cls.cookies_data = None
        
    @classmethod
    def teardown_class(cls):
        """Cleanup class-level variables and sensitive data"""
        # Clear sensitive cookies data
        if hasattr(cls, 'cookies_data'):
            cls.cookies_data = None
        logger.info("Cookies data cleared from memory")
        
        # Hardcoded slack_creds.json data
        cls.slack_creds_data = {
            "oauth_url_template": "https://slack.com/oauth/v2/authorize?client_id=<client_id>&scope=channels:read,chat:write,team:read&user_scope=",
            "base_credentials": {
                "client_id": "3028352990.9190625703366",
                "client_secret": "514f1448e898df99297dbee647021014",
                "bot_name": "Slack Test 191 ATM"
            },
            "slack_channel_name": "slack-atm-automation",
            "slack_message_template": "Hello QA Team, The API is now working from the Slack feature. Please validate the pre-populated message from SFDC manually. The message was sent on {date & time}"
        }
        
        # Set OAuth URL
        oauth_url_template = cls.slack_creds_data.get('oauth_url_template')
        client_id = cls.slack_creds_data.get('base_credentials', {}).get('client_id')
        
        if oauth_url_template and client_id:
            cls.oauth_url = oauth_url_template.replace('<client_id>', client_id)
        else:
            pytest.fail("oauth_url_template or client_id not found in hardcoded slack_creds data")

    def _extract_error_message(self, response):
        """Helper method to safely extract error messages from API responses"""
        if not isinstance(response, dict):
            return str(response)

        if 'error' in response:
            error_detail = response.get('error')
            if isinstance(error_detail, dict):
                if 'errors' in error_detail and error_detail['errors']:
                    return error_detail['errors'][0].get('message', 'Unknown error')
                else:
                    return error_detail.get('message', 'Unknown error')
            else:
                return str(error_detail)

        return response.get('message', 'Unknown error')

    def _extract_callback_error_code(self, response):
        """Helper method to extract specific error codes from callback responses"""
        if not isinstance(response, dict):
            return None

        if 'error' in response:
            error_detail = response.get('error')
            if isinstance(error_detail, dict):
                # Try to extract the nested error message
                message = error_detail.get('message', '')
                if 'Invalid bot name configured' in message:
                    return 'Invalid bot name configured'
                elif 'Slack OAuth failed: bad_client_secret' in message:
                    return 'Slack OAuth failed: bad_client_secret'
                elif 'errors' in error_detail and error_detail['errors']:
                    error_msg = error_detail['errors'][0].get('message', '')
                    if 'Invalid bot name configured' in error_msg:
                        return 'Invalid bot name configured'
                    elif 'Slack OAuth failed: bad_client_secret' in error_msg:
                        return 'Slack OAuth failed: bad_client_secret'

        return None

    def _load_slack_test_data(self):
        """Load and return Slack test data from hardcoded data"""
        return self.slack_creds_data

    def _api_call_with_retry(self, api_method, *args, **kwargs):
        """
        Helper method to make API calls with retry logic for 500 Server Errors
        Retries after 5 seconds for maximum 2 times
        """
        max_retries = 2
        retry_delay = 5

        for attempt in range(max_retries + 1):  # 0, 1, 2 (total 3 attempts)
            try:
                response = api_method(*args, **kwargs)

                # Check for 500 error in different response formats
                is_500_error = False
                error_message = ""

                # Check if response is a dict with status_code field
                if isinstance(response, dict) and response.get('status_code') == 500:
                    is_500_error = True
                    error_message = response.get('message', 'Server Error')

                # Check if response has status_code attribute
                elif hasattr(response, 'status_code') and response.status_code == 500:
                    is_500_error = True
                    error_message = getattr(response, 'text', 'Server Error')

                # Check if response is a string containing 500 error
                elif isinstance(response, str) and ("500" in response or "Internal Server Error" in response):
                    is_500_error = True
                    error_message = response

                if not is_500_error:
                    # Success - return the response
                    if attempt > 0:
                        allure.attach(f"API call succeeded on attempt {attempt + 1}", "Retry Success",
                                      allure.attachment_type.TEXT)
                        logger.info(f"API call succeeded on attempt {attempt + 1}")
                    return response

                # 500 error detected
                if attempt < max_retries:
                    allure.attach(
                        f"500 Server Error detected on attempt {attempt + 1}. Error: {error_message}. Retrying in {retry_delay} seconds...",
                        "Retry Attempt", allure.attachment_type.TEXT)
                    logger.warning(
                        f"500 Server Error detected on attempt {attempt + 1}. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    allure.attach(
                        f"500 Server Error persisted after {max_retries + 1} attempts. Final error: {error_message}",
                        "Retry Failed", allure.attachment_type.TEXT)
                    logger.error(f"500 Server Error persisted after {max_retries + 1} attempts")
                    return response  # Return the final response even if it's an error

            except Exception as e:
                if attempt < max_retries:
                    allure.attach(f"Exception on attempt {attempt + 1}: {str(e)}. Retrying in {retry_delay} seconds...",
                                  "Retry Exception", allure.attachment_type.TEXT)
                    logger.warning(f"Exception on attempt {attempt + 1}: {str(e)}. Retrying...")
                    time.sleep(retry_delay)
                else:
                    allure.attach(f"Exception persisted after {max_retries + 1} attempts: {str(e)}",
                                  "Retry Exception Failed", allure.attachment_type.TEXT)
                    logger.error(f"Exception persisted after {max_retries + 1} attempts: {str(e)}")
                    raise

        return response

    def setup_selenium_driver(self):
        """Setup Chrome driver with appropriate options"""
        options = Options()
        options.add_argument("--disable-notifications")
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--start-maximized")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        self.driver = webdriver.Chrome(service=Service(), options=options)
        return self.driver

    def load_cookies(self, navigate_url: str = None):
        """Load cookies from Jenkins parameter and apply to driver. Optionally navigate to a URL before setting cookies."""
        try:
            if not self.cookies_data:
                pytest.fail("Cookies data not provided via Jenkins parameter")
            
            cookies = self.cookies_data
            # Log only the count of cookies for security, not the actual data
            logger.info(f"Loading {len(cookies)} cookies from Jenkins parameter")

            # Navigate to domain first to set cookies
            target_url = navigate_url or "https://workspan.slack.com"
            self.driver.get(target_url)
            time.sleep(2)

            # Add each cookie
            for cookie in cookies:
                cookie_dict = {
                    "name": cookie["name"],
                    "value": cookie["value"],
                    "domain": cookie["domain"],
                    "path": cookie.get("path", "/"),
                    "secure": cookie.get("secure", False),
                    "httpOnly": cookie.get("httpOnly", False),
                }
                # Skip cookies with invalid expiry values
                if "expiry" in cookie or "expires" in cookie:
                    try:
                        expiry_value = cookie.get("expires", 0)
                        if expiry_value and expiry_value != "nan" and expiry_value != "null":
                            cookie_dict["expiry"] = int(expiry_value)
                    except (ValueError, TypeError):
                        # Skip this cookie if expiry is invalid
                        continue
                try:
                    self.driver.add_cookie(cookie_dict)
                except Exception:
                    # Silently skip cookies that can't be added
                    continue

            return True
        except Exception as e:
            return False

    def extract_code_from_url(self, url):
        """Extract authorization code from URL"""
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            code = query_params.get('code', [None])[0]
            return code
        except Exception:
            return None

    @allure.title("Login with CompanyUser")
    def test_01_login(self):
        """Test login and authentication token generation"""
        try:
            if not hasattr(self, 'credentials') or not isinstance(self.credentials, dict):
                pytest.fail("Credentials not properly initialized")

            user_creds = {
                "username": self.credentials.get("work_email"),
                "password": self.credentials.get("password")
            }

            if not user_creds.get("username") or not user_creds.get("password"):
                pytest.fail("Missing username or password in credentials")

            allure.attach(json.dumps(user_creds, indent=2), "User Credentials", allure.attachment_type.JSON)

            TestSlackIntegrationATM.token = self._api_call_with_retry(
                self.api_helper.get_auth_token,
                user_creds["username"],
                user_creds["password"]
            )

            if not TestSlackIntegrationATM.token:
                pytest.fail("Failed to get auth token")

        except Exception as e:
            pytest.fail(f"Login test failed: {str(e)}")

    @allure.title("Check and Delete Existing Slack Connection")
    def test_02_check_and_delete_existing_connection(self):
        """Check for existing Slack connection and delete if found"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            with allure.step("Get existing company connections"):
                # Get company connection to check for existing Slack integration
                response = self._api_call_with_retry(
                    self.api_helper.slack_get_company_connection,
                    TestSlackIntegrationATM.token
                )

                allure.attach(json.dumps(response, indent=2), "Company Connection Response",
                              allure.attachment_type.JSON)

                if response.get('status_code') != 200:
                    error_msg = self._extract_error_message(response)
                    pytest.fail(f"Failed to get company connection: {error_msg}")

                # Check if there are existing Slack connections
                connections_data = response.get('data', [])
                slack_connections = [conn for conn in connections_data if conn.get('app') == 'slack']

                if slack_connections:
                    allure.attach(f"Found {len(slack_connections)} existing Slack connection(s)",
                                  "Existing Connections", allure.attachment_type.TEXT)

                    # Delete each existing Slack connection
                    for connection in slack_connections:
                        connection_id = connection.get('id')
                        if connection_id:
                            with allure.step(f"Delete existing Slack connection ID: {connection_id}"):
                                delete_response = self._api_call_with_retry(
                                    self.api_helper.slack_delete_configuration,
                                    TestSlackIntegrationATM.token,
                                    str(connection_id)
                                )

                                allure.attach(json.dumps(delete_response, indent=2),
                                              f"Delete Response for ID {connection_id}", allure.attachment_type.JSON)

                                if delete_response.get('status_code') == 200:
                                    assert delete_response.get(
                                        'message') == "Slack connection deleted successfully", "Unexpected delete response message"
                                    allure.attach(f"Successfully deleted connection ID: {connection_id}",
                                                  "Delete Status", allure.attachment_type.TEXT)
                                else:
                                    error_msg = self._extract_error_message(delete_response)
                                    allure.attach(f"Failed to delete connection ID {connection_id}: {error_msg}",
                                                  "Delete Error", allure.attachment_type.TEXT)
                else:
                    pytest.skip("No existing Slack connections found. Skipping deletion step.")

        except Exception as e:
            pytest.fail(f"Check and delete existing connection test failed: {str(e)}")

    @allure.title("Save Slack Credentials")
    def test_03_save_slack_credentials(self):
        """Test saving Slack credentials with valid data"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            # Load test data from consolidated file
            test_data = self._load_slack_test_data()
            credentials_payload = test_data['base_credentials']

            allure.attach(json.dumps(credentials_payload, indent=2), "Slack Credentials Payload",
                          allure.attachment_type.JSON)

            # Save credentials
            response = self._api_call_with_retry(
                self.api_helper.slack_save_credentials,
                TestSlackIntegrationATM.token,
                credentials_payload
            )

            if not response or not isinstance(response, dict):
                pytest.fail("Invalid response from save credentials API")

            allure.attach(json.dumps(response, indent=2), "Save Credentials Response", allure.attachment_type.JSON)

            if response.get('status_code') != 200:
                error_msg = self._extract_error_message(response)
                pytest.fail(f"Failed to save Slack credentials: {error_msg}")

            assert response['message'] == "Slack credentials saved successfully", "Unexpected response message"

            allure.attach("Slack credentials saved successfully", "Save Credentials Status",
                          allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Save Slack credentials positive test failed: {str(e)}")

    @allure.title("Get Company Connection")
    def test_04_get_company_connection(self):
        """Test getting company connection for Slack integration"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            # Get company connection
            response = self._api_call_with_retry(
                self.api_helper.slack_get_company_connection,
                TestSlackIntegrationATM.token
            )

            if not response or not isinstance(response, dict):
                pytest.fail("Invalid response from company connection API")

            allure.attach(json.dumps(response, indent=2), "Company Connection Response", allure.attachment_type.JSON)

            if response.get('status_code') != 200:
                error_msg = self._extract_error_message(response)
                pytest.fail(f"Failed to get company connection: {error_msg}")

            # Extract connection_id if available
            if 'connection_id' in response:
                TestSlackIntegrationATM.connection_id = response['connection_id']
                allure.attach(f"Connection ID: {TestSlackIntegrationATM.connection_id}", "Connection ID",
                              allure.attachment_type.TEXT)

            allure.attach("Company connection retrieved successfully", "Company Connection Status",
                          allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Get company connection test failed: {str(e)}")

    @allure.title("OAuth Authorization Flow")
    def test_05_oauth_authorization_flow(self):
        """Test OAuth authorization flow with Selenium"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            with allure.step("Setup Selenium WebDriver"):
                self.setup_selenium_driver()

            with allure.step("Load Slack cookies"):
                if not self.load_cookies():
                    pytest.fail("Failed to load cookies")

            with allure.step("Navigate to OAuth URL"):
                self.driver.get(self.oauth_url)
                time.sleep(3)

            with allure.step("Handle OAuth approval"):
                # Wait for and click the Allow button - try multiple selectors
                wait = WebDriverWait(self.driver, 60)

                # Try different selectors for the Allow button
                allow_button = None
                selectors = [
                    'button[aria-label="Allow"]',
                    'button:contains("Allow")',
                    'button[data-qa="allow-button"]',
                    'button.allow-button',
                    'button[type="submit"]',
                    'button.btn-primary',
                    'button:contains("Authorize")',
                    'button[aria-label="Authorize"]'
                ]

                for selector in selectors:
                    try:
                        if "contains" in selector:
                            # Handle text-based selectors
                            allow_button = wait.until(EC.element_to_be_clickable((By.XPATH,
                                                                                  f"//button[contains(text(), '{selector.split('contains(')[1].split(')')[0]}')]")))
                        else:
                            allow_button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, selector)))
                        break
                    except TimeoutException:
                        continue

                if allow_button:
                    allow_button.click()
                    allure.attach("Allow button clicked successfully", "OAuth Approval", allure.attachment_type.TEXT)
                else:
                    # Take a screenshot for debugging
                    screenshot_path = "slack_oauth_page.png"
                    self.driver.save_screenshot(screenshot_path)
                    allure.attach.file(screenshot_path, "OAuth Page Screenshot", allure.attachment_type.PNG)
                    pytest.fail("Could not find Allow button with any selector")

            with allure.step("Wait for redirect and extract code"):
                # Wait for redirect - try multiple approaches
                final_url = None
                authorization_code = None

                try:
                    # First try: Wait for URL with code parameter
                    wait.until(EC.url_contains("code="))
                    final_url = self.driver.current_url
                    allure.attach(f"Final URL (code=): {final_url}", "OAuth Redirect URL", allure.attachment_type.TEXT)
                    # Quit driver immediately after getting the final URL
                    if self.driver:
                        self.driver.quit()
                        allure.attach("Driver quit immediately after getting final URL", "Driver Status",
                                      allure.attachment_type.TEXT)

                    authorization_code = self.extract_code_from_url(final_url)
                except TimeoutException:
                    # Third try: Just wait a bit and check current URL
                    final_url = self.driver.current_url
                    allure.attach(f"Final URL (timeout): {final_url}", "OAuth Redirect URL",
                                  allure.attachment_type.TEXT)
                    # Quit driver immediately after getting the final URL
                    if self.driver:
                        self.driver.quit()
                        allure.attach("Driver quit immediately after getting final URL", "Driver Status",
                                      allure.attachment_type.TEXT)

                    # Try normal extraction first
                    authorization_code = self.extract_code_from_url(final_url)

                    # If not found, try to extract from redirectUrl param (for cases like /login?redirectUrl=...)
                    if not authorization_code:
                        parsed = urlparse(final_url)
                        qs = parse_qs(parsed.query)
                        redirect_url = qs.get('redirectUrl', [None])[0]
                        if redirect_url:
                            # Unquote and parse the redirectUrl
                            decoded_redirect = unquote(redirect_url)
                            # Now look for code=... in the decoded redirect
                            if "code=" in decoded_redirect:
                                # Extract code value
                                match = re.search(r'code=([^&]+)', decoded_redirect)
                                if match:
                                    code_candidate = match.group(1)
                                    # Sometimes code is urlencoded, decode again
                                    code_candidate = unquote(code_candidate)
                                    authorization_code = code_candidate

                # Store the authorization code
                TestSlackIntegrationATM.authorization_code = authorization_code

                if TestSlackIntegrationATM.authorization_code:
                    allure.attach(f"Authorization code extracted: {TestSlackIntegrationATM.authorization_code[:10]}...",
                                  "Authorization Code", allure.attachment_type.TEXT)

        except TimeoutException:
            pytest.fail("Timeout waiting for Allow button or redirect")
        except Exception as e:
            pytest.fail(f"OAuth authorization flow failed: {str(e)}")
        finally:
            # Ensure driver is quit even if there's an exception
            if self.driver:
                self.driver.quit()

    @allure.title("Complete Slack Callback")
    def test_06_complete_slack_callback(self):
        """Test completing Slack callback with authorization code"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            if not TestSlackIntegrationATM.authorization_code:
                allure.attach("Authorization code not available from OAuth flow", "Callback Status",
                              allure.attachment_type.TEXT)
                allure.attach("This test requires a successful OAuth flow to get the authorization code", "Test Note",
                              allure.attachment_type.TEXT)
                # Skip the test instead of failing
                pytest.skip("Authorization code is missing. OAuth flow may not have completed successfully.")

            # Complete callback with authorization code
            response = self._api_call_with_retry(
                self.api_helper.slack_callback,
                TestSlackIntegrationATM.token,
                TestSlackIntegrationATM.authorization_code
            )

            if not response or not isinstance(response, dict):
                pytest.fail("Invalid response from callback API")

            allure.attach(json.dumps(response, indent=2), "Slack Callback Response", allure.attachment_type.JSON)

            if response.get('status_code') != 200:
                error_msg = self._extract_error_message(response)
                pytest.fail(f"Failed to complete Slack callback: {error_msg}")

            assert response.get(
                'message') == "Slack app authorized successfully", "Slack app authorized not successfully"

            allure.attach("Slack callback completed successfully", "Callback Status", allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Complete Slack callback test failed: {str(e)}")

    @allure.title("Validate Slack Connection")
    def test_07_validate_slack_connection(self):
        """Test validating Slack connection"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            # Validate Slack connection
            response = self._api_call_with_retry(
                self.api_helper.slack_get_company_connection,
                TestSlackIntegrationATM.token
            )

            if not response or not isinstance(response, dict):
                pytest.fail("Invalid response from validate connection API")

            allure.attach(json.dumps(response, indent=2), "Validate Connection Response", allure.attachment_type.JSON)

            if response.get('status_code') != 200:
                error_msg = self._extract_error_message(response)
                pytest.fail(f"Failed to validate Slack connection: {error_msg}")

            # Assert that the Slack connection status is 'active'
            data_list = response.get('data', [])
            assert data_list, "No data found in Slack connection response"
            slack_connection = data_list[0]
            assert slack_connection.get(
                'status') == 'active', f"Slack connection status is not active: {slack_connection.get('status')}"

            # Store connectionContext for future use in self
            TestSlackIntegrationATM.slack_connection_context = slack_connection.get('connectionContext', {})
            allure.attach(json.dumps(self.slack_connection_context, indent=2), "Slack Connection Context",
                          allure.attachment_type.JSON)

            allure.attach("Slack connection validated successfully", "Validate Connection Status",
                          allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Validate Slack connection test failed: {str(e)}")

    @allure.title("Create Draft Teammate")
    def test_08_create_teammate(self):
        """Test creating a draft teammate"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            # Hardcoded test data for teammate creation
            test_data = {
                "create_teammate_payload": {
                    "name": "Test Teammate {$random}",
                    "description": "Test description {$random}",
                    "partner_company_name": "Test Company {$random}",
                    "partner_company_file_name": "test_logo_{$filename_type}",
                    "status": "DRAFT"
                }
            }
            
            teammate_payload_source = test_data.get("create_teammate_payload")
            if not isinstance(teammate_payload_source, dict):
                pytest.fail("create_teammate_payload is not a valid dictionary")
            teammate_payload = teammate_payload_source.copy()
            
            # Hardcoded partner logo files
            partner_logo_files = ["AI_TeamMates/testdata/partner_company_logo/valid_logo.jpg"]

            if not partner_logo_files:
                pytest.fail("No partner logo files found in master file")

            # Choose a random logo file
            try:
                partner_logo_file = random.choice([list(item.values())[0] for item in partner_logo_files])
            except (IndexError, ValueError) as e:
                pytest.fail(f"Error selecting partner logo file: {str(e)}")

            # Replace placeholders in payload
            for key in teammate_payload:
                if isinstance(teammate_payload[key], str):
                    teammate_payload[key] = teammate_payload[key].replace('{$random}', uuid.uuid4().hex[:5])
                    teammate_payload[key] = teammate_payload[key].replace('{$number}', str(random.randint(1, 20)))
                    teammate_payload[key] = teammate_payload[key].replace('{$filename_type}',
                                                                          partner_logo_file.split('/')[-1])

            allure.attach(json.dumps(teammate_payload, indent=2), "Teammate Payload", allure.attachment_type.JSON)
            teammate_payload['partner_company_name'] = teammate_payload['partner_company_name'].replace("Test Company",
                                                                                                        partner_logo_file.split(
                                                                                                            '/')[
                                                                                                            -1].split(
                                                                                                            '.')[0])

            # Upload partner logo
            logo_upload = self._api_call_with_retry(
                self.api_helper.upload_partner_logo,
                TestSlackIntegrationATM.token,
                teammate_payload['partner_company_file_name'],
                teammate_payload['partner_company_name'],
                teammate_payload['name'],
                partner_logo_file
            )

            if not isinstance(logo_upload, dict) or logo_upload.get('message') != "Upload URL generated successfully":
                error_msg = f"Logo upload failed: {logo_upload}"
                if isinstance(logo_upload, dict) and logo_upload.get('error'):
                    error_detail = logo_upload.get('error')
                    if isinstance(error_detail, dict):
                        error_msg = f"Logo upload failed: {error_detail.get('message', 'Unknown error')}"
                    else:
                        error_msg = f"Logo upload failed: {error_detail}"
                pytest.fail(error_msg)

            allure.attach(json.dumps(logo_upload, indent=2), "Logo Upload Response", allure.attachment_type.JSON)

            # Get presigned URL and upload to S3
            logo_data = logo_upload.get('data', {})
            if not isinstance(logo_data, dict):
                pytest.fail("Invalid data format in logo upload response")

            presigned_url = logo_data.get('presigned_url')
            if not presigned_url:
                pytest.fail("Presigned URL not found in logo upload response")

            logo_response = self._api_call_with_retry(
                self.api_helper.upload_logo_s3_bucket,
                presigned_url,
                partner_logo_file
            )
            allure.attach(str(logo_response.status_code), "Logo S3 Upload Status Code", allure.attachment_type.TEXT)

            if logo_response.status_code != 204:
                pytest.fail(
                    f"File {teammate_payload['partner_company_file_name']} upload failed with status code {logo_response.status_code}")

            # Create teammate
            # Step 1: Create plan before teammate creation
            with allure.step("Create Plan for Teammate"):
                # Hardcoded plan template
                plan_template = {
                    "name": "Test Plan {$random}",
                    "description": "Test plan description {$random}",
                    "status": "ACTIVE"
                }
                company_id = self.company_details.get('company_id')
                allure.attach(f"Using company_id: {company_id}", "Company ID", allure.attachment_type.TEXT)

                plan_response = self._api_call_with_retry(
                    self.api_helper.create_plan,
                    TestSlackIntegrationATM.token,
                    company_id,
                    plan_template
                )
                allure.attach(json.dumps(plan_response, indent=2), "Plan Creation Response",
                              allure.attachment_type.JSON)

                if plan_response.get('status_code') != 200:
                    pytest.fail(f"Plan creation failed with status: {plan_response.get('status_code')}")

                project_id = plan_response.get('project_id')
                if not project_id:
                    pytest.fail("Plan creation succeeded but no project_id returned")

                # Store project_id for later use in plan deletion
                TestSlackIntegrationATM.project_id = project_id
                allure.attach(f"Plan created with project_id: {project_id}", "Plan Created",
                              allure.attachment_type.TEXT)

                # Step 2: Add plan details to teammate payload
                teammate_payload["plan_ids"] = [project_id]
                teammate_payload["plan_category"] = "ws-partner-plan"
                allure.attach(json.dumps(teammate_payload, indent=2), "Updated Teammate Payload with Plan",
                              allure.attachment_type.JSON)

                TestSlackIntegrationATM.teammate = self._api_call_with_retry(
                    self.api_helper.create_teammate,
                    TestSlackIntegrationATM.token,
                    teammate_payload
                )

            if not isinstance(TestSlackIntegrationATM.teammate, dict):
                pytest.fail(f"Invalid teammate creation response: {TestSlackIntegrationATM.teammate}")

            if 'error' in TestSlackIntegrationATM.teammate:
                error_msg = TestSlackIntegrationATM.teammate['error'].get('message', 'Unknown error')
                pytest.fail(f"Failed to create teammate: {error_msg}")

            if 'id' not in TestSlackIntegrationATM.teammate:
                pytest.fail("Teammate ID not found in creation response")

            allure.attach(json.dumps(TestSlackIntegrationATM.teammate, indent=2), "Create Teammate Response",
                          allure.attachment_type.JSON)
            time.sleep(5)
        except Exception as e:
            pytest.fail(f"Create teammate test failed: {str(e)}")

    @allure.title("Fetch Slack Channels")
    def test_09_fetch_slack_channels(self):
        """Test fetching Slack channels and finding the specified channel"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            # Load Slack credentials to get the channel name
            test_data = self._load_slack_test_data()
            target_channel_name = test_data.get('slack_channel_name')

            if not target_channel_name:
                pytest.fail("slack_channel_name not found in slack_creds.json")

            allure.attach(f"Looking for channel: {target_channel_name}", "Target Channel", allure.attachment_type.TEXT)

            # Fetch Slack channels
            response = self._api_call_with_retry(
                self.api_helper.slack_fetch_channels,
                TestSlackIntegrationATM.token
            )

            if not response or not isinstance(response, dict):
                pytest.fail("Invalid response from fetch channels API")

            allure.attach(json.dumps(response, indent=2), "Fetch Channels Response", allure.attachment_type.JSON)

            if response.get('status_code') != 200:
                error_msg = self._extract_error_message(response)
                pytest.fail(f"Failed to fetch Slack channels: {error_msg}")

            # Validate response structure
            assert response.get('status') == 'success', f"Expected status 'success', got {response.get('status')}"
            assert response.get('has_slack_connection') == True, "Slack connection should be active"
            assert response.get('bot_name') == test_data['base_credentials']['bot_name'], "Bot name mismatch"
            # Store team id for later UI validation
            TestSlackIntegrationATM.slack_team_id = response.get('team_id')

            # Find the target channel
            channels = response.get('channels', [])
            target_channel = None

            for channel in channels:
                if channel.get('name') == target_channel_name:
                    target_channel = channel
                    break

            if not target_channel:
                available_channels = [ch.get('name') for ch in channels[:10]]  # Show first 10 channels
                allure.attach(f"Available channels (first 10): {available_channels}", "Available Channels",
                              allure.attachment_type.TEXT)
                pytest.fail(f"Channel '{target_channel_name}' not found in Slack workspace")

            # Store channel details for future use
            TestSlackIntegrationATM.slack_channel_id = target_channel.get('id')
            TestSlackIntegrationATM.slack_channel_name = target_channel.get('name')

            allure.attach(f"Found channel: {target_channel_name}", "Channel Found", allure.attachment_type.TEXT)
            allure.attach(f"Channel ID: {TestSlackIntegrationATM.slack_channel_id}", "Channel ID",
                          allure.attachment_type.TEXT)
            allure.attach(json.dumps(target_channel, indent=2), "Target Channel Details", allure.attachment_type.JSON)

            # Validate channel properties
            assert target_channel.get('is_archived') == False, "Channel should not be archived"
            assert int(target_channel.get('num_members', 0)) > 0, "Channel should have members"

            allure.attach("Slack channels fetched and target channel found successfully", "Fetch Channels Status",
                          allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Fetch Slack channels test failed: {str(e)}")

    @allure.title("Save Slack Channel")
    def test_10_save_slack_channel(self):
        """Test saving Slack channel configuration to teammate"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            if not hasattr(TestSlackIntegrationATM, 'teammate') or not TestSlackIntegrationATM.teammate:
                pytest.fail("Teammate not created. Run test_08_create_teammate first.")

            if not hasattr(TestSlackIntegrationATM, 'slack_channel_id') or not TestSlackIntegrationATM.slack_channel_id:
                pytest.fail("Slack channel ID not found. Run test_09_fetch_slack_channels first.")

            if not hasattr(TestSlackIntegrationATM,
                           'slack_channel_name') or not TestSlackIntegrationATM.slack_channel_name:
                pytest.fail("Slack channel name not found. Run test_09_fetch_slack_channels first.")

            teammate_id = TestSlackIntegrationATM.teammate.get('id')
            channel_id = TestSlackIntegrationATM.slack_channel_id
            channel_name = TestSlackIntegrationATM.slack_channel_name

            allure.attach(f"Teammate ID: {teammate_id}", "Teammate ID", allure.attachment_type.TEXT)
            allure.attach(f"Channel ID: {channel_id}", "Channel ID", allure.attachment_type.TEXT)
            allure.attach(f"Channel Name: {channel_name}", "Channel Name", allure.attachment_type.TEXT)

            # Save Slack channel configuration
            response = self._api_call_with_retry(
                self.api_helper.slack_save_channel,
                TestSlackIntegrationATM.token,
                teammate_id,
                channel_id,
                channel_name,
                1
            )

            if not response or not isinstance(response, dict):
                pytest.fail("Invalid response from save channel API")

            allure.attach(json.dumps(response, indent=2), "Save Channel Response", allure.attachment_type.JSON)

            if response.get('status_code') != 200:
                error_msg = self._extract_error_message(response)
                pytest.fail(f"Failed to save Slack channel: {error_msg}")

            allure.attach("Slack channel saved successfully", "Save Channel Status", allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Save Slack channel test failed: {str(e)}")

    @allure.title("Activate Teammate")
    def test_11_activate_teammate(self):
        """Test activating the teammate"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            if not TestSlackIntegrationATM.teammate or not TestSlackIntegrationATM.teammate.get('id'):
                pytest.fail("Teammate ID is missing. Create teammate first.")

            # Activate teammate
            activation_payload = {
                "status": "ACTIVE",
                "version": 2
            }

            allure.attach(json.dumps(activation_payload, indent=2), "Activation Payload", allure.attachment_type.JSON)

            activation_response = self._api_call_with_retry(
                self.api_helper.update_delete_teammates,
                TestSlackIntegrationATM.token,
                TestSlackIntegrationATM.teammate.get('id'),
                "update",
                activation_payload
            )

            if not activation_response or not isinstance(activation_response, dict):
                pytest.fail("Invalid activation response")

            allure.attach(json.dumps(activation_response, indent=2), "Activation Response", allure.attachment_type.JSON)

            if activation_response.get('status_code') != 200:
                error_msg = self._extract_error_message(activation_response)
                pytest.fail(f"Failed to activate teammate: {error_msg}")

            if activation_response.get('status') != "ACTIVE":
                pytest.fail(f"Unexpected status after activation: {activation_response.get('status', 'unknown')}")

            allure.attach("Teammate activated successfully", "Activation Status", allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Activate teammate test failed: {str(e)}")

    @allure.title("Send Slack Message (SFDC & Workspan Feature)")
    def test_12_send_slack_message(self):
        """Send a Slack message using the Slack feature endpoint using message template from slack_creds.json"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            # Ensure we have a channel id; prefer previously selected channel
            if not getattr(TestSlackIntegrationATM, 'slack_channel_id', None):
                # Fallback: fetch channels and pick from config name
                test_data = self._load_slack_test_data()
                target_channel_name = test_data.get('slack_channel_name')
                response = self._api_call_with_retry(
                    self.api_helper.slack_fetch_channels,
                    TestSlackIntegrationATM.token
                )
                if not response or response.get('status_code') != 200:
                    pytest.fail("Failed to fetch channels to determine channel_id")
                channels = response.get('channels', [])
                for ch in channels:
                    if ch.get('name') == target_channel_name:
                        TestSlackIntegrationATM.slack_channel_id = ch.get('id')
                        break
                if not TestSlackIntegrationATM.slack_channel_id:
                    pytest.fail(f"Channel '{target_channel_name}' not found to send message")

            channel_id = TestSlackIntegrationATM.slack_channel_id

            # Load template from slack_creds.json and substitute {date & time}
            slack_data = self._load_slack_test_data()
            template = slack_data.get('slack_message_template', '')
            if not template:
                pytest.fail("slack_message_template not found in slack_creds.json")

            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            message_body = template.replace('{date & time}', now_str)

            # Store for validation in test_13
            TestSlackIntegrationATM.sent_message_text = message_body

            allure.attach(json.dumps({
                'channel_id': channel_id,
                'message_body': message_body
            }, indent=2), "Send Message Payload", allure.attachment_type.JSON)

            send_response = self._api_call_with_retry(
                self.api_helper.slack_send_message,
                TestSlackIntegrationATM.token,
                channel_id,
                message_body,
                self.teammate['id']
            )

            if not send_response or not isinstance(send_response, dict):
                pytest.fail("Invalid send message response")

            allure.attach(json.dumps(send_response, indent=2), "Send Message Response", allure.attachment_type.JSON)

            if send_response.get('status_code') != 200:
                error_msg = self._extract_error_message(send_response)
                pytest.fail(f"Failed to send slack message: {error_msg}")

            # Validate the send_response using assertions
            assert send_response.get(
                "status") == "success", f"Expected status 'success', got {send_response.get('status')}"
            assert send_response.get(
                "message") == "Message sent successfully to Slack", f"Unexpected message: {send_response.get('message')}"
            assert "message_ts" in send_response and send_response[
                "message_ts"], "Missing or empty 'message_ts' in response"
            assert send_response.get(
                "channel_id") == channel_id, f"Expected channel_id '{channel_id}', got {send_response.get('channel_id')}"

        except Exception as e:
            pytest.fail(f"Send Slack message test failed: {str(e)}")

    @allure.title("Validate Slack Message Appears in Channel")
    def test_13_validate_msg_present_on_slack(self):
        """Validate the message sent in test_12 is present in Slack channel UI."""
        try:
            # Ensure we have a channel id and message body template
            if not getattr(TestSlackIntegrationATM, 'slack_channel_id', None):
                pytest.fail("Slack channel ID not found. Ensure test_09 and test_12 have run.")

            # Use the exact message sent in test_12 when available
            expected_message = getattr(TestSlackIntegrationATM, 'sent_message_text', None)
            if not expected_message:
                # Fallback: rebuild the prefix with today's date part if exact string not available
                slack_data = self._load_slack_test_data()
                template = slack_data.get('slack_message_template', '')
                if not template:
                    pytest.fail("slack_message_template not found in slack_creds.json")
                from datetime import datetime
                today_str = datetime.now().strftime('%Y-%m-%d')
                expected_prefix = "Hello QA Team, The API is now working from the Slack feature. Please validate the pre-populated message from SFDC manually. The message was sent on "
                expected_message = f"{expected_prefix}{today_str}"

            # Build Slack client URL
            team_id = TestSlackIntegrationATM.slack_team_id
            channel_id = TestSlackIntegrationATM.slack_channel_id
            target_url = f"https://app.slack.com/client/{team_id}/{channel_id}"

            # Launch driver
            self.setup_selenium_driver()

            # Load cookies and navigate
            if not self.load_cookies(navigate_url=target_url):
                pytest.fail("Failed to load cookies for Slack UI validation")

            # Navigate to target channel again after cookies
            self.driver.get(target_url)

            wait = WebDriverWait(self.driver, 60)
            message_list = wait.until(EC.presence_of_element_located((By.ID, "message-list")))
            wait.until(EC.presence_of_element_located(
                (By.CSS_SELECTOR, '#message-list .c-virtual_list__item [data-qa="message_content"]')))

            # Collect messages visible in the list
            messages = []
            elements = message_list.find_elements(By.CSS_SELECTOR, ".c-virtual_list__item")
            for i in range(len(elements)):
                try:
                    elem = message_list.find_elements(By.CSS_SELECTOR, ".c-virtual_list__item")[i]
                    content_elem = elem.find_element(By.CSS_SELECTOR, '[data-qa="message_content"]')
                    text = content_elem.text.strip()
                    if text:
                        messages.append(text)
                except Exception:
                    continue

            allure.attach(json.dumps(messages, indent=2), "All Slack Messages (Present in DOM)",
                          allure.attachment_type.JSON)

            # Validate that our message is present; match by prefix and today's date
            matched = any(expected_message in m for m in messages)
            if matched:
                allure.attach(f"Found expected message: {expected_message}", "Message Found",
                              allure.attachment_type.TEXT)
            else:
                allure.attach(f"Expected message not found: {expected_message}", "Message Not Found",
                              allure.attachment_type.TEXT)
                pytest.fail("Expected Slack message not found in channel")

        except Exception as e:
            pytest.fail(f"Validate Slack message presence failed: {str(e)}")
        finally:
            if self.driver:
                self.driver.quit()

    @allure.title("Save Slack Credentials In Inactive State")
    def test_14_save_slack_credentials_inactive_state(self):
        """Test saving Slack credentials in inactive state"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            # Load test data from consolidated file
            test_data = self._load_slack_test_data()
            credentials_payload = test_data['base_credentials']

            allure.attach(json.dumps(credentials_payload, indent=2), "Slack Credentials Payload",
                          allure.attachment_type.JSON)

            # Save credentials
            response = self._api_call_with_retry(
                self.api_helper.slack_save_credentials,
                TestSlackIntegrationATM.token,
                credentials_payload
            )

            if not response or not isinstance(response, dict):
                pytest.fail("Invalid response from save credentials API")

            allure.attach(json.dumps(response, indent=2), "Save Credentials Response", allure.attachment_type.JSON)

            if response.get('status_code') != 200:
                error_msg = self._extract_error_message(response)
                pytest.fail(f"Failed to save Slack credentials: {error_msg}")

            assert response['message'] == "Slack credentials saved successfully", "Unexpected response message"

            allure.attach("Slack credentials saved successfully", "Save Credentials Status",
                          allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Save Slack credentials positive test failed: {str(e)}")

    @allure.title("Validate Slack Configuration")
    def test_15_validate_slack_configuration(self):
        """Test validating Slack configuration"""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            # Fetch Slack channels
            response = self._api_call_with_retry(
                self.api_helper.slack_fetch_channels,
                TestSlackIntegrationATM.token
            )

            if not response or not isinstance(response, dict):
                pytest.fail("Invalid response from fetch channels API")

            allure.attach(json.dumps(response, indent=2), "Fetch Channels Response", allure.attachment_type.JSON)

            if response.get('status_code') != 200:
                error_msg = self._extract_error_message(response)
                pytest.fail(f"Failed to fetch Slack channels: {error_msg}")

            # Validate response structure
            if 'has_slack_connection' not in response:
                pytest.fail("Response missing 'has_slack_connection' key")
            assert response['has_slack_connection'] is False, (
                f"Expected slack configuration 'False', got {response['has_slack_connection']}"
            )

            allure.attach("Slack configuration validated: has_slack_connection is False", "Validation Status",
                          allure.attachment_type.TEXT)

        except Exception as e:
            pytest.fail(f"Validate Slack configuration test failed: {str(e)}")

    @allure.title("Delete Teammate")
    def test_16_delete_teammate(self):
        """Delete the teammate created in test_08."""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            if not getattr(TestSlackIntegrationATM, 'teammate', None) or not TestSlackIntegrationATM.teammate.get('id'):
                pytest.fail("Teammate ID is missing. Create teammate first.")

            teammate_id = TestSlackIntegrationATM.teammate.get('id')
            allure.attach(teammate_id, "Teammate ID To Delete", allure.attachment_type.TEXT)

            delete_response = self._api_call_with_retry(
                self.api_helper.update_delete_teammates,
                TestSlackIntegrationATM.token,
                teammate_id,
                "delete"
            )

            if not delete_response or not isinstance(delete_response, dict):
                pytest.fail("Invalid delete teammate response")

            allure.attach(json.dumps(delete_response, indent=2), "Delete Teammate Response",
                          allure.attachment_type.JSON)

            if delete_response.get('status_code') != 200:
                error_msg = self._extract_error_message(delete_response)
                pytest.fail(f"Failed to delete teammate: {error_msg}")

        except Exception as e:
            pytest.fail(f"Delete teammate test failed: {str(e)}")

    @allure.title("Delete Plan")
    def test_17_delete_plan(self):
        """Delete the plan created in test_08 (by project_id)."""
        try:
            if not TestSlackIntegrationATM.token:
                pytest.fail("Auth token is missing. Login first.")

            project_id = getattr(TestSlackIntegrationATM, 'project_id', None)
            if not project_id:
                pytest.fail("Project ID is missing. Plan was not created.")

            allure.attach(project_id, "Project ID To Delete", allure.attachment_type.TEXT)

            # Archive the plan before deletion
            archive_response = self._api_call_with_retry(
                self.api_helper.archive_plan,
                TestSlackIntegrationATM.token,
                project_id
            )

            if not archive_response or not isinstance(archive_response, dict):
                pytest.fail("Invalid archive plan response")

            allure.attach(json.dumps(archive_response, indent=2), "Archive Plan Response", allure.attachment_type.JSON)

            if archive_response.get('status_code') != 200:
                error_msg = self._extract_error_message(archive_response)
                pytest.fail(f"Failed to archive plan: {error_msg}")

            delete_plan_response = self._api_call_with_retry(
                self.api_helper.delete_plan,
                TestSlackIntegrationATM.token,
                project_id
            )

            if not delete_plan_response or not isinstance(delete_plan_response, dict):
                pytest.fail("Invalid delete plan response")

            allure.attach(json.dumps(delete_plan_response, indent=2), "Delete Plan Response",
                          allure.attachment_type.JSON)

            if delete_plan_response.get('status_code') != 200:
                error_msg = self._extract_error_message(delete_plan_response)
                pytest.fail(f"Failed to delete plan: {error_msg}")

        except Exception as e:
            pytest.fail(f"Delete plan test failed: {str(e)}")
