from base64 import b64decode
from io import BytesIO
from typing import Annotated, Any

from pydantic import Field
from pymisp import MISPAttribute, MISPEvent, PyMISP, PyMISPError
from pymisp.tools import make_binary_objects
from tracecat_registry import RegistrySecret, registry, secrets

SLEEP_TIME = 300
SSL = True

misp_secrets = RegistrySecret(
    name="misp",
    keys=["MISP_APIKEY", "MISP_URL"],
)


@registry.register(
    default_title="Misp create event.",
    display_group="Misp",
    description="Create a new misp event with a file.",
    namespace="misp",
    secrets=[misp_secrets],
)
def create_event(
    data: Annotated[str, Field(description="The data of the file.")],
    filename: Annotated[str, Field(description="Filename of the sample")],
) -> str:
    misp = PyMISP(secrets.get("MISP_URL"), secrets.get("MISP_APIKEY"), SSL, "json")

    event = MISPEvent()
    event.info = f"Malware pipeline file : {filename}"

    data = BytesIO(b64decode(data))
    fo, po, so = make_binary_objects(pseudofile=data, filename=filename)
    if fo:
        for att in fo.attributes:
            att.to_ids = False
        event.add_object(fo)
        if po:
            event.add_object(po)

    response = misp.add_event(event, pythonify=True)

    if response:
        return response.uuid
    else:
        raise PyMISPError(f"Failed to created event for file {filename}")


def create_attribute(
    ioc: tuple[str, str], dataType: str, sandbox: str | None = None
) -> MISPAttribute:
    att = MISPAttribute()
    att.category = "Network activity"
    att.value = ioc[0]
    att.type = dataType
    att.to_ids = ioc[1].lower() == "malicious"
    att.add_tag(ioc[1])
    if sandbox:
        att.add_tag(sandbox)
    return att


@registry.register(
    default_title="Misp add iocs to an event.",
    display_group="Misp",
    description="Add a list of IOCs to an already created event",
    namespace="misp",
    secrets=[misp_secrets],
)
def add_iocs(
    event: Annotated[str, Field(description="uuid of the event to add to.")],
    iocs: Annotated[dict[str, Any], Field(description="Dictionary of iocs to add.")],
    sandbox: Annotated[
        str | None, Field(description="Sandbox that provided the iocs.")
    ] = None,
) -> dict[str, Any]:
    misp = PyMISP(secrets.get("MISP_URL"), secrets.get("MISP_APIKEY"), SSL, "json")

    for url in iocs.get("urls", []):
        att = create_attribute(url, "url", sandbox)
        misp.add_attribute(event, att)
    for ip in iocs.get("ips", []):
        att = create_attribute(ip, "ip-dst", sandbox)
        misp.add_attribute(event, att)
    for domain in iocs.get("domains", []):
        att = create_attribute(domain, "domain", sandbox)
        misp.add_attribute(event, att)

    return {"success": "success"}


def tag():
    pass
