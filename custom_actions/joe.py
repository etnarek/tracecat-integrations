import json
from base64 import b64decode
from io import BytesIO
from typing import Annotated, Any

import jbxapi
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets

SANDBOX_NAME = "joe"


joe_secrets = RegistrySecret(
    name="joe",
    keys=["JOE_APIKEY"],
    optional_keys=["JOE_APIURL"],
)


@registry.register(
    default_title="Joe submit file",
    display_group="Joe",
    description="Submit a file to joe sandbox.",
    namespace="joe",
    secrets=[joe_secrets],
)
def submit(
    data: Annotated[str, Field(description="The data to submit to joe sandbox.")],
    filename: Annotated[str, Field(description="Filename of the sample")],
) -> dict[str, Any]:
    joe = jbxapi.JoeSandbox(
        apikey=secrets.get("JOE_APIKEY"),
        apiurl=secrets.get("JOE_APIURL"),
        accept_tac=True,
    )
    sample = (filename, BytesIO(b64decode(data)))

    r = joe.submit_sample(sample)
    submission_id = r["submission_id"]
    return submission_id


def tag_malicious(is_malicious):
    return "malicious" if is_malicious == "true" else "unknown"


@registry.register(
    default_title="Joe get report",
    display_group="Joe",
    description="Get the IOCs back for a joe sandbox submission.",
    namespace="joe",
    secrets=[joe_secrets],
)
def get_report(
    submission_id: Annotated[
        str, Field(description="Id of the submission in joe sandbox.")
    ],
):
    joe = jbxapi.JoeSandbox(
        apikey=secrets.get("JOE_APIKEY"),
        apiurl=secrets.get("JOE_APIURL"),
        accept_tac=True,
    )
    info = joe.submission_info(submission_id)
    if info["status"] != "finished":
        return {"status": "pending"}

    malicious = info["most_relevant_analysis"]["detection"]

    iocs_r = json.loads(
        joe.analysis_download(info["most_relevant_analysis"]["webid"], "iocjson")[1]
    )
    urls, ips, domains = [], [], []

    urlinfo = iocs_r["analysis"]["urlinfo"]
    if urlinfo:
        urls = [
            (x["@name"], tag_malicious(x["@malicious"]), SANDBOX_NAME)
            for x in urlinfo["url"]
        ]
    ipinfo = iocs_r["analysis"]["ipinfo"]
    if ipinfo:
        ips = [
            (x["@ip"], tag_malicious(x["@malicious"]), SANDBOX_NAME)
            for x in ipinfo["ip"]
        ]
    domaininfo = iocs_r["analysis"]["domaininfo"]
    if domaininfo:
        domains = [
            (x["@name"], tag_malicious(x["@malicious"]), SANDBOX_NAME)
            for x in domaininfo["domain"]
        ]

    return {
        "malicious": malicious,
        "ioc": {"urls": urls, "domains": domains, "ips": ips},
        "status": "finished",
        "sandbox": SANDBOX_NAME,
    }
