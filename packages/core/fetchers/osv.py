import asyncio
import httpx
from ..config import settings


async def fetch_package_osv(package_name: str, version: str, ecosystem: str):
    async with httpx.AsyncClient() as client:
        res = await client.post(
            url=settings.osv_base_url,
            json={
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem,
                },
                "version": version,
            }
        )

        res.raise_for_status()
        data = res.json()

        return data


if __name__ == "__main__":
    print(asyncio.run(fetch_package_osv("requests", "2.28.1", "PyPI")))
