import flask
import os
import click
import httpx
import nacl
import nacl.signing
import time
import json
from flask.json import jsonify
import threading
import tomli

# confirm variables are here
with open("config.toml", "rb") as f:
    configuration = tomli.load(f)

TOKEN = configuration["bot"]["token"]
KEY = configuration["bot"]["key"]
ID = configuration["bot"]["id"]
IMAGE = configuration["container"]["image"]
PORTS = configuration["container"]["ports"]
ENVIRONMENT = configuration["container"].get("environment", {})


@click.command("sync")
def sync_commands() -> None:
    r = httpx.post(
        f"https://discord.com/api/v10/applications/{ID}/commands",
        headers={"Authorization": f"Bot {TOKEN}"},
        json={
            "name": "run",
            "description": "run a specific Docker image tag",
            "options": [
                {
                    "type": 3,
                    "name": "tag",
                    "description": "the tag to run",
                    "required": True,
                }
            ],
        },
    )
    r.raise_for_status()


app = flask.Flask(__name__)
app.cli.add_command(sync_commands)


@app.route("/")
def index() -> str:
    return "yeah, this works"


key = nacl.signing.VerifyKey(bytes.fromhex(KEY))


@app.route("/interact", methods=["POST"])
def interact() -> flask.Response:
    signature = flask.request.headers["X-Signature-Ed25519"]
    timestamp = flask.request.headers["X-Signature-Timestamp"]
    body = flask.request.data.decode("utf-8")

    if not timestamp.isdecimal() or int(timestamp) + 5 < time.time():
        flask.abort(401, "too old")

    try:
        key.verify(f"{timestamp}{body}".encode(), bytes.fromhex(signature))
    except Exception:
        flask.abort(401, "incorrect signature")

    r = json.loads(body)
    if r["type"] == 1:
        return jsonify({"type": 1})

    if r["type"] == 2 and r["data"]["name"] == "run":
        # run a docker image
        tag = r["data"]["options"][0]["value"]
        # :/
        t = threading.Thread(target=run_image, kwargs={"tag": tag, "token": r["token"]})
        t.start()
        return jsonify(
            {
                "type": 5,
            }
        )

    return jsonify({"type": 4, "data": {"content": "unknown command", "flags": 64}})


podman_address = f"/run/user/{os.getuid()}/podman/podman.sock"


def run_image(tag: str, token: str) -> None:
    transport = httpx.HTTPTransport(uds=podman_address)
    with httpx.Client(transport=transport, timeout=60) as client:
        r = client.post(
            "http://podman/v5.0.0/libpod/images/pull",
            params={"reference": f"{IMAGE}:{tag}", "quiet": True},
        )
        r.raise_for_status()

        pulls = r.json()

        if "error" in pulls:
            r = httpx.patch(
                f"https://discord.com/api/v10/webhooks/{ID}/{token}/messages/@original",
                json={
                    "content": f"Errored! `{pulls['error']}`",
                },
            )
            r.raise_for_status()
            return

        r = httpx.patch(
            f"https://discord.com/api/v10/webhooks/{ID}/{token}/messages/@original",
            json={
                "content": "Pulled image",
            },
        )
        r.raise_for_status()

        r = client.post(
            "http://podman/v5.0.0/libpod/containers/create",
            json={
                "image": pulls["id"],
                "portmappings": [
                    {"container_port": port["container"], "host_port": port["host"]}
                    for port in PORTS
                ],
                "env": ENVIRONMENT
            },
        )
        r.raise_for_status()

        containers = r.json()

        if "error" in containers:
            r = httpx.patch(
                f"https://discord.com/api/v10/webhooks/{ID}/{token}/messages/@original",
                json={
                    "content": f"Errored! `{pulls['error']}`",
                },
            )
            r.raise_for_status()
            return

        r = httpx.patch(
            f"https://discord.com/api/v10/webhooks/{ID}/{token}/messages/@original",
            json={
                "content": "Created container",
            },
        )
        r.raise_for_status()
        container_id = containers["Id"]

        # stop old containers and start new ones
        r = client.get(
            "http://podman/v5.0.0/libpod/containers/json",
            params={
                # "all": True,
                "filters": f'{{"ancestor": ["{IMAGE}"]}}'
            },
        )
        r.raise_for_status()
        old_containers = r.json()

        for container in old_containers:
            if container["Id"] != container_id:
                r = client.post(
                    f"http://podman/v5.0.0/libpod/containers/{container['Id']}/stop"
                )
                r.raise_for_status()

        r = client.post(f"http://podman/v5.0.0/libpod/containers/{container_id}/start")
        r.raise_for_status()

        r = httpx.patch(
            f"https://discord.com/api/v10/webhooks/{ID}/{token}/messages/@original",
            json={
                "content": "Started container",
            },
        )
        r.raise_for_status()
