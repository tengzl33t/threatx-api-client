import asyncio
import os
from unittest import TestCase

import aiohttp
from threatx_api_client import (
    Client,
    TXAPIIncorrectCommandError,
    TXAPIIncorrectTokenError,
    TXAPIJSONError,
    TXAPIResponseError,
)


class TestClient(TestCase):
    """Main API Client test class."""

    @classmethod
    def setUpClass(cls) -> None:
        """Setting up Main API Client class for tests."""
        api_key = cls.api_key = os.getenv("TX_API_KEY")
        api_env = cls.api_env = "api.protect"
        cls.tenant = os.getenv("TX_API_TEST_TENANT")
        cls.api_client = Client(api_env, api_key)

    def test_empty_token(self):
        """Test for no API token provided."""
        with self.assertRaises(TXAPIIncorrectTokenError):
            Client("prod", "")

    async def __process_with_session(self, func, client):
        async with aiohttp.ClientSession(base_url=client.base_url) as session:
            return await func(session)

    def test_incorrect_token(self):
        """Test for incorrect API token provided."""
        with self.assertRaises(TXAPIIncorrectTokenError):
            client = Client("prod", "a34456456gfd")
            asyncio.run(self.__process_with_session(client._Client__login, client))  # Private method test hack

    def test_correct_token_and_env(self):
        """Test for correct API token and environment provided."""
        Client("api.protect", self.api_key)

    def test_sites_incorrect_command(self):
        """Test for incorrect command in payload provided."""
        with self.assertRaises(TXAPIIncorrectCommandError):
            self.api_client.sites({
                "command": "AyyLmao",
                "customer_name": self.tenant
            })

    def test_list_sites_incorrect_customer(self):
        """Test for incorrect customer in payload provided."""
        response = self.api_client.sites({
            "command": "list",
            "customer_name": "fffamogus"
        })

        assert isinstance(response, TXAPIResponseError)

    def test_json_error_503_exception(self):
        """Test for 503 error returned."""
        api_client = Client(self.api_env, self.api_key)
        api_client.headers = {"Host": "cocojambo"}
        response = api_client.sites({
            "command": "list",
            "customer_name": "test"
        })
        self.assertIsInstance(response, TXAPIJSONError)
        self.assertEqual(response.status_code, 503)

    def test_json_error_403_exception(self):
        """Test for 403 error returned."""
        api_client = Client(self.api_env, self.api_key)
        api_client.headers = {"Connection": "X-F5-Auth-Token"}
        response = api_client.sites({
            "command": "list",
            "customer_name": "test"
        })
        self.assertIsInstance(response, TXAPIJSONError)
        self.assertEqual(response.status_code, 403)

    def test_list_sites(self):
        """Test for 'sites' method 'list' command."""
        response = self.api_client.sites({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_get_customers(self):
        """Test for 'customers' method 'get' command."""
        response = self.api_client.customers({
            "command": "get",
            "name": self.tenant
        })
        self.assertIsInstance(response, dict)

    def test_get_customers_list(self):
        """Test for 'customers' method 'get' command."""
        response = self.api_client.customers([{
            "command": "get",
            "name": self.tenant
        }])
        self.assertIsInstance(response, list)

    def test_list_users(self):
        """Test for 'users' method 'list' command."""
        response = self.api_client.users({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_users_marker_var_single(self):
        """Test for 'users' method 'list' command."""
        response = self.api_client.users({
            "command": "list",
            "customer_name": self.tenant,
            "marker_var": "test"
        })
        self.assertIsInstance(response, dict)

    def test_list_users_marker_var_list(self):
        """Test for 'users' method 'list' command."""
        response = self.api_client.users([{
            "command": "list",
            "customer_name": self.tenant,
            "marker_var": "test"
        }])
        self.assertIsInstance(response, list)

    def test_get_templates(self):
        """Test for 'templates' method 'get' command."""
        response = self.api_client.templates({
            "command": "get",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, dict)

    def test_list_sensors(self):
        """Test for 'sensors' method 'list' command."""
        response = self.api_client.sensors({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_services(self):
        """Test for 'services' method 'list' command."""
        response = self.api_client.services({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_entities(self):
        """Test for 'entities' method 'list' command."""
        response = self.api_client.entities({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_subscriptions(self):
        """Test for 'subscriptions' method 'list' command."""
        response = self.api_client.subscriptions({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_blacklist_lists(self):
        """Test for 'lists' method 'list_blacklist' command."""
        response = self.api_client.lists({
            "command": "list_blacklist",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_customer_rules(self):
        """Test for 'rules' method 'list_customer_rules' command."""
        response = self.api_client.rules({
            "command": "list_customer_rules",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)
