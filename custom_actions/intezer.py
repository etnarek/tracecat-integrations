from base64 import b64decode
from io import BytesIO
from time import sleep
from typing import Annotated, Any

import requests
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets

SLEEP_TIME = 300
BASE_URL = "https://analyze.intezer.com/api/v2-0"

intezer_secrets = RegistrySecret(
    name="intezer",
    keys=["INTEZER_APIKEY"],
)


@registry.register(
    default_title="Intezer submit file",
    display_group="Intezer",
    description="Submit a file to intezer and wait for the IOCs back",
    namespace="intezer",
    secrets=[intezer_secrets],
)
def submit(
    data: Annotated[str, Field(description="The data to submit to joe sandbox.")],
    filename: Annotated[str, Field(description="Filename of the sample")],
) -> dict[str, Any]:
    sample = (filename, BytesIO(b64decode(data)))

    response = requests.post(
        BASE_URL + "/get-access-token", json={"api_key": secrets.get("INTEZER_APIKEY")}
    )
    response.raise_for_status()
    session = requests.session()
    session.headers["Authorization"] = session.headers["Authorization"] = (
        "Bearer %s" % response.json()["result"]
    )

    files = {"file": sample}
    response = session.post(BASE_URL + "/analyze", files=files)
    assert response.status_code == 201

    while response.status_code != 200:
        sleep(SLEEP_TIME)
        result_url = response.json()["result_url"]
        response = session.get(BASE_URL + result_url)
        response.raise_for_status()

    report = response.json()

    malicious = report["result"]["verdict"]

    urls, ips, domains = [], [], []

    if report["result"].get("network"):
        urls = [
            (x["ioc"], x["classification"])
            for x in report["result"]["network"]
            if x["type"] == "url"
        ]
        ips = [
            (x["ioc"], x["classification"])
            for x in report["result"]["network"]
            if x["type"] == "ip"
        ]
        domains = [
            (x["ioc"], x["classification"])
            for x in report["result"]["network"]
            if x["type"] == "domain"
        ]

    return {
        "malicious": malicious,
        "ioc": {"urls": urls, "domains": domains, "ips": ips},
    }
