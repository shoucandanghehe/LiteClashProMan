import base64
from typing import List, Union, cast

from ..model.clash import SS, Vmess
from ..model.clash.proxy import Cipher
from ..utils import Download


def decode(sub: str) -> "SS":
    """Format the ShadowSocks proxy like ss://{base64encode}#{name}@{server}:{port}"""
    base64_encoded, name_and_other = sub[5:].split("#")

    cipher_password, server_and_port = (
        base64.b64decode(f"{base64_encoded}===").decode().split("@")
    )
    cipher, password = cipher_password.split(":")

    server, port = server_and_port.split(":")
    name = name_and_other.split("@")[1].split(".")[0]

    return SS(
        name=name,
        server=server,
        type="ss",
        port=int(port),
        cipher=cast(Cipher, cipher),
        password=password,
        udp=True,
    )


async def get(url: str) -> List[Union[SS, Vmess]]:
    return [
        decode(sub)
        for sub in base64.decodebytes(await Download.content(url)).decode().split("\n")
        if sub.startswith("ss://")
    ]
