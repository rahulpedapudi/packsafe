import os

from dotenv import load_dotenv
from google.cloud import bigquery
from google.oauth2 import service_account

from ..schemas.pypi import StatsResponse

load_dotenv()

CREDS_PATH = os.getenv("CREDS_PATH")
PROJECT_NAME = os.getenv("PROJECT_NAME")


def get_stats(package: str, version: str | None, interval: int):
    credentials = service_account.Credentials.from_service_account_file(CREDS_PATH)

    client = bigquery.Client(credentials=credentials, project=PROJECT_NAME)

    query = f"""
        SELECT
        file.version,
        COUNT(*) as download_count
        FROM
        `bigquery-public-data.pypi.file_downloads`
        WHERE
        project = '{package}'
        AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {interval} DAY)
        GROUP BY
        file.version
        ORDER BY
        download_count DESC
        LIMIT 5
    """
    df = client.query(query).to_dataframe()

    # Convert DataFrame rows into a list of dicts:
    data = df.to_dict(orient="records")

    return StatsResponse(package_name=package, version=version, stats=data)
