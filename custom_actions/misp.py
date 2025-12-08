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
    default_title="Misp create event",
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
    event.add_tag("befish")

    data = BytesIO(b64decode(data))
    fo, po, so = make_binary_objects(pseudofile=data, filename=filename)
    if fo:
        for att in fo.attributes:
            att.to_ids = False
            att.add_tag("befish")
        event.add_object(fo)
    if po:
        event.add_object(po)

    response = misp.add_event(event, pythonify=True)

    if response:
        return response.uuid
    else:
        raise PyMISPError(f"Failed to created event for file {filename}")


def ioc_exists(event: MISPEvent, ioc: str) -> MISPAttribute | None:
    for att in event.attributes:
        if att.value == ioc:
            return att
    return None


def create_attribute(
    ioc: tuple[str, str], dataType: str, event: MISPEvent, misp: PyMISP
) -> None:
    att = ioc_exists(event, ioc[0])
    if not att:
        att = MISPAttribute()
        att.category = "Network activity"
        att.value = ioc[0]
        att.type = dataType
        att.to_ids = False
        att = misp.add_attribute(event, att, pythonify=True)
        event.attributes.append(att)
    if not att.to_ids and ioc[1].lower() == "malicious":
        att.to_ids = True
    att.add_tag(ioc[1].lower())
    att.add_tag(ioc[2])
    misp.update_attribute(att)


@registry.register(
    default_title="Misp add iocs to event",
    display_group="Misp",
    description="Add a list of IOCs to an already created event",
    namespace="misp",
    secrets=[misp_secrets],
)
def add_iocs(
    event_uuid: Annotated[str, Field(description="uuid of the event to add to.")],
    iocs: Annotated[
        list[dict[str, Any]], Field(description="List of dictionaries of iocs to add.")
    ],
) -> dict[str, Any]:
    misp = PyMISP(secrets.get("MISP_URL"), secrets.get("MISP_APIKEY"), SSL, "json")
    event = misp.get_event(event_uuid, pythonify=True)

    for ioc in iocs:
        for url in ioc.get("urls", []):
            create_attribute(url, "url", event, misp)
        for ip in ioc.get("ips", []):
            create_attribute(ip, "ip-dst", event, misp)
        for domain in ioc.get("domains", []):
            create_attribute(domain, "domain", event, misp)

    misp.update_event(event)
    return {"success": "success"}


def tag():
    pass
