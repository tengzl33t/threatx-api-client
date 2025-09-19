import asyncio
import importlib.metadata
from json import JSONDecodeError

import aiohttp
from aiohttp import ClientSession

from threatx_api_client.exceptions import (
    TXAPIIncorrectCommandError,
    TXAPIIncorrectTokenError,
    TXAPIJSONError,
    TXAPIResponseError,
)

tx_api_session_token = ""


class AsyncClient:
    """Main Async API Client class."""

    def __init__(
            self, api_env: str, api_key: str,
            headers: dict | None = None, verify_ssl: bool = True,
    ) -> None:
        """Async Main Client class initializer."""
        if not api_key:
            msg = "Please provide TX API Key."
            raise TXAPIIncorrectTokenError(msg)

        self.api_path = "tx_api"
        self.api_env = api_env
        self.api_key = api_key

        self.base_url = self.__get_api_env_host(self.api_env)

        self.headers = {
            "User-Agent":
                f"ThreatX-API-Client/{importlib.metadata.version('threatx_api_client')}",
        }

        if headers:
            self.headers = {**self.headers, **headers}

        self.verify_ssl = verify_ssl

    def __get_api_env_host(self, api_env: str) -> str:
        old_host_parts = {
            "prod": "",
            "xplat": "protect"
        }

        if api_env in old_host_parts:
            part = (f"-{old_host_parts.get(api_env)}"
                    if old_host_parts.get(api_env) else "")
            return f"https://api{part}.threatx.io"

        return f"https://{api_env}.threatx.io"

    def __generate_api_link(self, api_ver: int) -> str:
        return f"/{self.api_path}/v{api_ver}"

    async def __post(self, session: ClientSession, path: str, post_payload: dict) -> dict:
        marker_var = post_payload.get("marker_var")
        clean_post_payload = post_payload.copy()
        clean_post_payload.pop("marker_var", None)

        async with session.post(path, json=clean_post_payload) as raw_response:
            try:
                response = await raw_response.json(content_type=None)
            except JSONDecodeError:
                raise TXAPIJSONError(
                    raw_response.status,
                    await raw_response.text(),
                    raw_response.headers.get("X-Request-ID"),
                    marker_var,
                ) from None

        response_ok_data = response.get("Ok")
        response_error_data = response.get("Error")

        if response_ok_data is not None:
            if marker_var:
                return {marker_var: response_ok_data}
            return response_ok_data

        global tx_api_session_token  # noqa: PLW0603

        if response_error_data == "Token Expired. Please re-authenticate.":
            post_payload.pop("token", None)
            tx_api_session_token = await self.__login(session)
            return await self.__post(session, path, {"token": tx_api_session_token, **post_payload})
        if response_error_data:
            error_msg = {marker_var: response_error_data} if marker_var else response_error_data
            raise TXAPIResponseError(error_msg)
        return {marker_var: response} if marker_var else response

    async def __process_response(self, path: str, available_commands: list, payloads: dict | list) -> dict | list:
        normalized_payloads = [payloads] if isinstance(payloads, dict) else payloads

        for payload in normalized_payloads:
            if payload.get("command") not in available_commands:
                raise TXAPIIncorrectCommandError(payload.get("command"))

        resolver = aiohttp.AsyncResolver()
        connector = aiohttp.TCPConnector(
            enable_cleanup_closed=True,
            verify_ssl=self.verify_ssl,
            keepalive_timeout=5,
            resolver=resolver,
        )
        session = aiohttp.ClientSession(
            base_url=self.base_url, headers=self.headers, connector=connector,
        )

        try:
            global tx_api_session_token  # noqa: PLW0603
            if not tx_api_session_token:
                tx_api_session_token = await self.__login(session)

            responses = await asyncio.gather(*(
                self.__post(
                    session,
                    path,
                    {"token": tx_api_session_token, **payload}) for payload in normalized_payloads
            ), return_exceptions=True)
        finally:
            await session.close()
            await resolver.close()

        if isinstance(payloads, dict):
            return responses[0]

        return responses

    async def __login(self, session: aiohttp.ClientSession) -> str:
        path = f"{self.__generate_api_link(1)}/login"

        if not self.api_key:
            msg = "Please provide TX API Key."
            raise TXAPIIncorrectTokenError(msg)

        response = await asyncio.gather(
            self.__post(
                session,
                path,
                {"command": "login", "api_token": self.api_key},
            ),
        )

        token_value = response[0]["token"]

        if not token_value:
            msg = "TX API Token is not correct!"
            raise TXAPIIncorrectTokenError(msg)

        return token_value

    async def api_keys(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """API Keys management.

        Method allows to manage API keys, allowing authorized users to
        create (and revoke) keys granting automated access to the ThreatX API.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(2)}/apikeys"

        available_commands = ["list", "new", "update", "revoke"]

        return await self.__process_response(url, available_commands, payloads)

    async def api_schemas(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """API schemas management.

        Method allows to manage API schemas.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/apischemas"

        available_commands = ["save", "list", "delete"]

        return await self.__process_response(url, available_commands, payloads)

    async def customers(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Customers management.

        Method allows to create, manage and remove customers.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/customers"

        available_commands = [
            "list",
            "list_all",
            "new",
            "get",
            "update",
            "delete",
            "list_api_keys",
            "new_api_key",
            "delete_api_key",
            "get_customer_config",
            "set_customer_config",
        ]

        return await self.__process_response(url, available_commands, payloads)

    async def users(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Users management.

        Method allows to create, manage and remove users.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/users"

        available_commands = [
            "list",
            "new",
            "get",
            "update",
            "delete",
        ]

        return await self.__process_response(url, available_commands, payloads)

    async def sites(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Sites management.

        Method allows to create, manage and remove sites.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(2)}/sites"

        available_commands = ["list", "new", "get", "delete", "update", "unset"]

        return await self.__process_response(url, available_commands, payloads)

    async def site_groups(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Site groups management.

        Method allows to create, manage and remove site groups.
        Site groups provide access control features similar to UNIX user groups,
        restricting access to ThreatX sites.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/sitegroups"

        available_commands = ["list", "save", "delete"]

        return await self.__process_response(url, available_commands, payloads)

    async def templates(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Templates management.

        Method allows to create, manage and remove customer templates.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/templates"

        available_commands = ["set", "get", "delete"]

        return await self.__process_response(url, available_commands, payloads)

    async def sensors(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Sensors information.

        Method provides information of on-premises deployed sensors and sensor metadata.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/sensors"

        available_commands = ["list", "tags"]

        return await self.__process_response(url, available_commands, payloads)

    async def services(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Services information.

        Method provides information on ThreatX system services
        and their public IP addresses.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/services"

        available_commands = ["list"]

        return await self.__process_response(url, available_commands, payloads)

    async def entities(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Entities management.

        Method allows to list and manage entities.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/entities"

        available_commands = [
            "list",
            "show",
            "state_changes",
            "risk_changes",
            "notes",
            "new_note",
            "reset",
            "block_entity",
            "blacklist_entity",
            "whitelist_entity",
            "watch_entity",
            "list_most_risky",
            "count",
        ]

        return await self.__process_response(url, available_commands, payloads)

    async def metrics(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Statistical metrics.

        Method provides statistical metrics on ThreatX system operations.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/metrics"

        available_commands = [
            "request_stats_by_hour",
            "request_stats_by_minute",
            "match_stats_by_hour",
            "block_stats_by_endpoint",
            "entity_stats_by_entity_by_quarter_hour",
            "rules_matched_by_ip_by_quarter_hour",
            "request_stats_by_endpoint",
            "threat_stats_by_endpoint",
            "threat_stats_by_hour",
            "threat_stats_by_quarter_hour",
            "threat_stats_by_site",
            "status_codes_by_site",
            "request_stats_hourly_by_site",
            "request_stats_hourly_by_endpoint",
        ]

        return await self.__process_response(url, available_commands, payloads)

    async def subscriptions(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Subscriptions management.

        Method allows to configure customer notification subscriptions.
        Subscriptions are used to receive notifications related
        to ThreatX events, delivered either via email,
        webhook, or through a log emitter communicating directly to an analyzer.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/subscriptions"

        available_commands = ["save", "delete", "list", "enable", "disable"]

        return await self.__process_response(url, available_commands, payloads)

    async def list_whitelist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get whitelist IPs.

        Method allows to get customer whitelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/whitelist"

        available_commands = ["list"]

        return await self.__process_response(url, available_commands, payloads)

    async def list_blacklist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get blacklist IPs.

        Method allows to get customer blacklisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/blacklist"

        available_commands = ["list"]

        return await self.__process_response(url, available_commands, payloads)

    async def list_blocklist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get blocklisted IPs.

        Method allows to get customer blocked IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/blocklist"

        available_commands = ["list"]

        return await self.__process_response(url, available_commands, payloads)

    async def list_mutelist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get mutelisted IPs.

        Method allows to get customer mutelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/mutelist"

        available_commands = ["list"]

        return await self.__process_response(url, available_commands, payloads)

    async def list_ignorelist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get ignorelisted IPs.

        Method allows to get customer ignorelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/ignorelist"

        available_commands = ["list"]

        return await self.__process_response(url, available_commands, payloads)

    async def global_tags(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Global tags management.

        Method allows to create new and provides information of
        global tags available for use.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/globaltags"

        available_commands = ["new", "list"]

        return await self.__process_response(url, available_commands, payloads)

    async def actor_tags(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Actor tags management.

        Method allows to create, manage and remove actor tags.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/actortags"

        available_commands = ["new", "list", "delete"]

        return await self.__process_response(url, available_commands, payloads)

    async def features(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Tenant Features information.

        Method provides information of tenant features enabled.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/features"

        available_commands = ["list", "query", "save", "delete"]

        return await self.__process_response(url, available_commands, payloads)

    async def metrics_tech(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """API Profiler information.

        Method provides information of customer API Profiler.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/metrics/tech"

        available_commands = ["list_endpoint_profiles", "list_site_profiles"]

        return await self.__process_response(url, available_commands, payloads)

    async def channels(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Channels management.

        Method allows to create, manage and remove customer channels.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/channels"

        available_commands = ["new", "list", "update"]

        return await self.__process_response(url, available_commands, payloads)

    async def global_settings(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Customer-wide settings.

        Method allows to get default customer-wide settings applied.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/globalsettings"

        available_commands = ["get"]

        return await self.__process_response(url, available_commands, payloads)

    async def dns_info(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """DNS configuration information.

        Method allows clients to retrieve information necessary for configuring DNS to address ThreatX services.
        :param list[dict]|dict payloads: API payloads or a single payload containing main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/dnsinfo"

        available_commands = ["list"]

        return await self.__process_response(url, available_commands, payloads)

    async def logs(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Customer logs.

        Method allows to get customer logs including audit logs, match events, etc.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/logs"

        available_commands = [
            "events",
            "entities",
            "blocks",
            "actions",
            "matches",
            "rule_hits",
            "sysinfo",
            "audit_log",
        ]

        return await self.__process_response(url, available_commands, payloads)

    async def logs_v2(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Customer logs.

        Method allows to get customer logs including block, match and audit events.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(2)}/logs"

        available_commands = [
            "block_events",
            "match_events",
            "audit_events",
        ]

        return await self.__process_response(url, available_commands, payloads)

    async def lists(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Lists management.

        Method allows to manage IP addresses within black, block and whitelists.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/lists"

        available_commands = [
            "list_blacklist",
            "list_blocklist",
            "list_whitelist",
            "list_ignorelist",
            "new_blacklist",
            "new_blocklist",
            "new_whitelist",
            "new_ignorelist",
            "bulk_new_blacklist",
            "bulk_new_blocklist",
            "bulk_new_whitelist",
            "bulk_new_ignorelist",
            "get_blacklist",
            "get_blocklist",
            "get_whitelist",
            "get_ignorelist",
            "delete_blacklist",
            "delete_blocklist",
            "delete_whitelist",
            "delete_ignorelist",
            "bulk_delete_blacklist",
            "bulk_delete_blocklist",
            "bulk_delete_whitelist",
            "bulk_delete_ignorelist",
            "ip_to_link",
        ]

        return await self.__process_response(url, available_commands, payloads)

    async def rules(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Rules management.

        Method allows to create, manage and remove customer rules.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/rules"

        available_commands = [
            "list_customer_rules",
            "list_whitelist_rules",
            "list_profiler_rules",
            "list_common_rules",
            "new_customer_rule",
            "new_whitelist_rule",
            "new_common_rule",
            "update_customer_rule",
            "update_whitelist_rule",
            "update_profiler_rule",
            "update_common_rule",
            "get_customer_rule",
            "get_whitelist_rule",
            "get_profiler_rule",
            "get_common_rule",
            "delete_customer_rule",
            "delete_whitelist_rule",
            "delete_profiler_rule",
            "delete_common_rule",
            "validate_rule",
        ]

        return await self.__process_response(url, available_commands, payloads)

class Client(AsyncClient):
    """Main API Client class."""
    def __init__(
            self, api_env: str, api_key: str,
            headers: dict | None = None, verify_ssl: bool = True,
    ) -> None:
        """Client class initializer."""
        super().__init__(api_env, api_key, headers, verify_ssl)

    def api_keys(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """API Keys management.

        Method allows to manage API keys, allowing authorized users to
        create (and revoke) keys granting automated access to the ThreatX API.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().api_keys(payloads))

    def api_schemas(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """API schemas management.

        Method allows to manage API schemas.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().api_schemas(payloads))

    def customers(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Customers management.

        Method allows to create, manage and remove customers.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().customers(payloads))

    def users(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Users management.

        Method allows to create, manage and remove users.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().users(payloads))

    def sites(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Sites management.

        Method allows to create, manage and remove sites.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().sites(payloads))

    def site_groups(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Site groups management.

        Method allows to create, manage and remove site groups.
        Site groups provide access control features similar to UNIX user groups,
        restricting access to ThreatX sites.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().site_groups(payloads))

    def templates(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Templates management.

        Method allows to create, manage and remove customer templates.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().templates(payloads))

    def sensors(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Sensors information.

        Method provides information of on-premises deployed sensors and sensor metadata.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().sensors(payloads))

    def services(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Services information.

        Method provides information on ThreatX system services
        and their public IP addresses.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().services(payloads))

    def entities(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Entities management.

        Method allows to list and manage entities.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().entities(payloads))

    def metrics(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Statistical metrics.

        Method provides statistical metrics on ThreatX system operations.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().metrics(payloads))

    def subscriptions(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Subscriptions management.

        Method allows to configure customer notification subscriptions.
        Subscriptions are used to receive notifications related
        to ThreatX events, delivered either via email,
        webhook, or through a log emitter communicating directly to an analyzer.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().subscriptions(payloads))

    def list_whitelist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get whitelist IPs.

        Method allows to get customer whitelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().list_whitelist(payloads))

    def list_blacklist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get blacklist IPs.

        Method allows to get customer blacklisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().list_blacklist(payloads))

    def list_blocklist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get blocklisted IPs.

        Method allows to get customer blocked IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().list_blocklist(payloads))

    def list_mutelist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get mutelisted IPs.

        Method allows to get customer mutelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().list_mutelist(payloads))

    def list_ignorelist(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Get ignorelisted IPs.

        Method allows to get customer ignorelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().list_ignorelist(payloads))

    def global_tags(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Global tags management.

        Method allows to create new and provides information of
        global tags available for use.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().global_tags(payloads))

    def actor_tags(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Actor tags management.

        Method allows to create, manage and remove actor tags.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().actor_tags(payloads))

    def features(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Tenant Features information.

        Method provides information of tenant features enabled.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().features(payloads))

    def metrics_tech(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """API Profiler information.

        Method provides information of customer API Profiler.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().metrics_tech(payloads))

    def channels(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Channels management.

        Method allows to create, manage and remove customer channels.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().channels(payloads))

    def global_settings(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Customer-wide settings.

        Method allows to get default customer-wide settings applied.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().global_settings(payloads))

    def dns_info(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """DNS configuration information.

        Method allows clients to retrieve information necessary for configuring DNS to address ThreatX services.
        :param list[dict]|dict payloads: API payloads or a single payload containing main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().dns_info(payloads))

    def logs(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Customer logs.

        Method allows to get customer logs including audit logs, match events, etc.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().logs(payloads))

    def logs_v2(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Customer logs.

        Method allows to get customer logs including block, match and audit events.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().logs_v2(payloads))

    def lists(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Lists management.

        Method allows to manage IP addresses within black, block and whitelists.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().lists(payloads))

    def rules(self, payloads: list[dict] | dict) -> list[dict] | dict:
        """Rules management.

        Method allows to create, manage and remove customer rules.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        return asyncio.run(super().rules(payloads))
