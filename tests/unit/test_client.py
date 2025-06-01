import asyncio
import os
from unittest import TestCase

from threatx_api_client import (
    Client,
    TXAPIIncorrectCommandError,
    TXAPIIncorrectTokenError,
    TXAPIResponseError,
)


class TestClient(TestCase):
    """Main API Client test class."""

    @classmethod
    def setUpClass(cls) -> None:
        """Setting up Main API Client class for tests."""
        api_key = cls.api_key = os.environ.get("TX_API_KEY")
        api_env = cls.api_env = "api.protect"
        cls.tenant = os.environ.get("TX_API_TEST_TENANT")
        cls.protect_client = Client(api_env, api_key)

    def test_empty_token(self):
        """Test for no API token provided."""
        with self.assertRaises(TXAPIIncorrectTokenError):
            Client("prod", "")

    def test_incorrect_token(self):
        """Test for incorrect API token provided."""
        with self.assertRaises(TXAPIIncorrectTokenError):
            client = Client("prod", "a34456456gfd")
            asyncio.run(client._Client__login())  # Private method test hack

    def test_correct_token_and_env(self):
        """Test for correct API token and environment provided."""
        Client("api.protect", self.api_key)

    def test_sites_incorrect_command(self):
        """Test for incorrect command in payload provided."""
        with self.assertRaises(TXAPIIncorrectCommandError):
            self.protect_client.sites({
                "command": "AyyLmao",
                "customer_name": self.tenant
            })

    def test_list_sites_incorrect_customer(self):
        """Test for incorrect customer in payload provided."""
        response = self.protect_client.sites({
            "command": "list",
            "customer_name": "fffamogus"
        })

        assert isinstance(response, TXAPIResponseError)

    def test_list_sites(self):
        """Test for 'sites' method 'list' command."""
        response = self.protect_client.sites({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_get_customers(self):
        """Test for 'customers' method 'get' command."""
        response = self.protect_client.customers({
            "command": "get",
            "name": self.tenant
        })
        self.assertIsInstance(response, dict)

    def test_get_customers_list(self):
        """Test for 'customers' method 'get' command."""
        response = self.protect_client.customers([{
            "command": "get",
            "name": self.tenant
        }])
        self.assertIsInstance(response, list)

    def test_list_users(self):
        """Test for 'users' method 'list' command."""
        response = self.protect_client.users({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_users_marker_var_single(self):
        """Test for 'users' method 'list' command."""
        response = self.protect_client.users({
            "command": "list",
            "customer_name": self.tenant,
            "marker_var": "test"
        })
        self.assertIsInstance(response, dict)

    def test_list_users_marker_var_list(self):
        """Test for 'users' method 'list' command."""
        response = self.protect_client.users([{
            "command": "list",
            "customer_name": self.tenant,
            "marker_var": "test"
        }])
        self.assertIsInstance(response, list)

    def test_get_templates(self):
        """Test for 'templates' method 'get' command."""
        response = self.protect_client.templates({
            "command": "get",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, dict)

    def test_list_sensors(self):
        """Test for 'sensors' method 'list' command."""
        response = self.protect_client.sensors({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_services(self):
        """Test for 'services' method 'list' command."""
        response = self.protect_client.services({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_entities(self):
        """Test for 'entities' method 'list' command."""
        response = self.protect_client.entities({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_subscriptions(self):
        """Test for 'subscriptions' method 'list' command."""
        response = self.protect_client.subscriptions({
            "command": "list",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_blacklist_lists(self):
        """Test for 'lists' method 'list_blacklist' command."""
        response = self.protect_client.lists({
            "command": "list_blacklist",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)

    def test_list_customer_rules(self):
        """Test for 'rules' method 'list_customer_rules' command."""
        response = self.protect_client.rules({
            "command": "list_customer_rules",
            "customer_name": self.tenant
        })
        self.assertIsInstance(response, list)
