import asyncio

from threatx_api_client import AsyncClient

tx_api = AsyncClient("prod", "")


async def get_customer_sites_data(customer_name: str, sites: list) -> list:
    """Getting sites data.

    Get tenant sites data with customer name and a list of sites provided.
    :param customer_name:
    :param sites:
    :return: API responses
    :rtype: list
    """
    return await tx_api.sites([
        {
            "command": "get",
            "customer_name": customer_name,
            "name": site,
        } for site in sites
    ])


if __name__ == "__main__":
    customer_name = ""
    sites = ["example.com", "test.local"]
    print(asyncio.run(get_customer_sites_data(customer_name, sites)))  # noqa: T201
