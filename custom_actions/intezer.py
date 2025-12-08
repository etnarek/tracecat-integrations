from base64 import b64decode
from io import BytesIO
from typing import Annotated

import requests
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets

BASE_URL = "https://analyze.intezer.com/api/v2-0"
SANDBOX_NAME = "intezer"

INTEZER_VERDICTS = {
    "trusted": "clean",
    "no_threats": "clean",
    "malicious": "malicious",
    "suspicious": "suspicious",
}

intezer_secrets = RegistrySecret(
    name="intezer",
    keys=["INTEZER_APIKEY"],
)


@registry.register(
    default_title="Intezer submit file",
    display_group="Intezer",
    description="Submit a file to intezer.",
    namespace="intezer",
    secrets=[intezer_secrets],
)
def submit(
    data: Annotated[str, Field(description="The data to submit to joe sandbox.")],
    filename: Annotated[str, Field(description="Filename of the sample.")],
) -> str:
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

    return response.json()["result_url"]


@registry.register(
    default_title="Intezer get report",
    display_group="Intezer",
    description="Get the result from an intezer submission.",
    namespace="intezer",
    secrets=[intezer_secrets],
)
def get_report(
    result_url: Annotated[
        str,
        Field(description="url returned by submit used to get the IOCs on intezer."),
    ],
):
    response = requests.post(
        BASE_URL + "/get-access-token", json={"api_key": secrets.get("INTEZER_APIKEY")}
    )
    response.raise_for_status()
    session = requests.session()
    session.headers["Authorization"] = session.headers["Authorization"] = (
        "Bearer %s" % response.json()["result"]
    )

    response = session.get(BASE_URL + result_url)
    response.raise_for_status()
    if response.status_code != 200:
        return {"status": "pending"}

    report = response.json()

    malicious = INTEZER_VERDICTS.get(report["result"]["verdict"].lower(), "unknown")

    response = session.get(BASE_URL + result_url + "/iocs")
    iocs = response.json()

    urls, ips, domains = [], [], []

    if iocs["result"].get("network"):
        urls = [
            (x["ioc"], x["classification"], SANDBOX_NAME)
            for x in iocs["result"]["network"]
            if x["type"] == "url"
        ]
        ips = [
            (x["ioc"], x["classification"], SANDBOX_NAME)
            for x in iocs["result"]["network"]
            if x["type"] == "ip"
        ]
        domains = [
            (x["ioc"], x["classification"], SANDBOX_NAME)
            for x in iocs["result"]["network"]
            if x["type"] == "domain"
        ]

    return {
        "malicious": malicious,
        "ioc": {"urls": urls, "domains": domains, "ips": ips},
        "status": "finished",
        "sandbox": SANDBOX_NAME,
    }
