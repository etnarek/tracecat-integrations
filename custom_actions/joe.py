from time import sleep
from typing import Annotated, Any

import jbxapi
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets

SLEEP_TIME = 300


joe_secrets = RegistrySecret(
    name="joe",
    keys=["JOE_APIKEY"],
    optional_keys=["JOE_APIURL"],
)


@registry.register(
    default_title="Joe submit file",
    display_group="Joe",
    description="Submit a file to joe sandbox and wait for the IOCs back",
    namespace="joe",
    secrets=joe_secrets,
)
def submit(
    data: Annotated[str, Field(description="The data to submit to joe sandbox.")],
    filename: Annotated[str, Field(description="Filename of the sample")],
) -> dict[str, Any]:
    joe = jbxapi.JoeSandbox(
        apikey=secrets.get("JOE_APIKEY"), apiurl=secrets.get("JOE_APIURL")
    )
    sample = (filename, data)

    r = joe.submit_sample(sample)
    submission_id = r["submission_id"]

    sleep(SLEEP_TIME)

    while True:
        info = joe.analysis_info(submission_id)
        if info["status"] == "finished":
            break
    malicious = info["detection"]

    iocs_r = joe.analysis_download(submission_id, "iocjson")
    urls = [(x["@name"], x["@malicious"]) for x in iocs_r["analysis"]["urlinfo"]["url"]]
    ips = [(x["@ip"], x["@malicious"]) for x in iocs_r["analysis"]["ipinfo"]["ip"]]
    domains = [
        (x["@name"], x["@malicious"])
        for x in iocs_r["analysis"]["domaininfo"]["domain"]
    ]

    return {
        "malicious": malicious,
        "ioc": {"urls": urls, "domains": domains, "ips": ips},
    }
