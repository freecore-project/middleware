import json

import bidict
import requests

from middlewared.rclone.base import BaseRcloneRemote
from middlewared.schema import Dict, Str
from middlewared.service import CallError, accepts

DRIVES_TYPES = bidict.bidict({
    "PERSONAL": "personal",
    "BUSINESS": "business",
    "DOCUMENT_LIBRARY": "documentLibrary",
})

DEFAULT_CLIENT_ID = "b15665d9-eda6-4092-8539-0eec376afd59"
DEFAULT_CLIENT_SECRET = "qtyfaBBYA403=unZUP40~_#"

GRAPH_URL = "https://graph.microsoft.com/v1.0"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
TOKEN_SCOPE = "Files.Read Files.ReadWrite Files.Read.All Files.ReadWrite.All Sites.Read.All offline_access"
TIMEOUT = 10


def refresh_access_token(client_id, client_secret, refresh_token):
    r = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "scope": TOKEN_SCOPE,
        },
        timeout=TIMEOUT,
    )
    if not r.ok:
        raise CallError(f"Unable to refresh the OneDrive access token: HTTP {r.status_code} {r.text[:500]}")
    return r.json()


def graph_get(path, access_token):
    return requests.get(f"{GRAPH_URL}{path}", headers={"Authorization": f"Bearer {access_token}"}, timeout=TIMEOUT)


class OneDriveRcloneRemote(BaseRcloneRemote):
    name = "ONEDRIVE"
    title = "Microsoft OneDrive"

    rclone_type = "onedrive"

    credentials_schema = [
        Str("client_id", title="OAuth Client ID", default=""),
        Str("client_secret", title="OAuth Client Secret", default=""),
        Str("token", title="Access Token", required=True, max_length=None),
        Str("drive_type", title="Drive Account Type", enum=list(DRIVES_TYPES.keys()), required=True),
        Str("drive_id", title="Drive ID", required=True),
    ]
    credentials_oauth = True
    refresh_credentials = ["token"]

    extra_methods = ["list_drives"]

    async def get_task_extra(self, task):
        return dict(
            drive_type=DRIVES_TYPES.get(task["credentials"]["attributes"]["drive_type"], ""),
        )

    @accepts(Dict(
        "onedrive_list_drives",
        Str("client_id", default=""),
        Str("client_secret", default=""),
        Str("token", required=True, max_length=None),
    ))
    def list_drives(self, credentials):
        """
        Lists all available drives and their types for given Microsoft OneDrive credentials.

        .. examples(websocket)::

            :::javascript
            {
              "id": "6841f242-840a-11e6-a437-00e04d680384",
              "msg": "method",
              "method": "cloudsync.onedrive_list_drives",
              "params": [{
                "client_id": "...",
                "client_secret": "",
                "token": "{...}",
              }]
            }

        Returns

            [{"drive_type": "PERSONAL", "drive_id": "6bb903a25ad65e46"}]
        """
        # Microsoft Graph directly, as upstream TrueNAS does since the abandoned
        # onedrivesdk package left FreeBSD (the internal development record).
        client_id = credentials["client_id"] or DEFAULT_CLIENT_ID
        client_secret = credentials["client_secret"] or DEFAULT_CLIENT_SECRET

        try:
            token = json.loads(credentials["token"])
            access_token = token["access_token"]
        except (ValueError, TypeError, KeyError):
            raise CallError("The OneDrive token is not a valid OAuth token JSON object")

        r = graph_get("/me/drives", access_token)
        if r.status_code == 401:
            if not token.get("refresh_token"):
                raise CallError("The OneDrive access token has expired and the token has no refresh token")
            access_token = refresh_access_token(client_id, client_secret, token["refresh_token"])["access_token"]
            r = graph_get("/me/drives", access_token)
        if not r.ok:
            raise CallError(f"Unable to list OneDrive drives: HTTP {r.status_code} {r.text[:500]}")

        result = [self._drive(drive) for drive in r.json().get("value", [])]

        # /me/drives does not always include the user's own drive
        # (https://github.com/rclone/rclone/issues/4068).
        r = graph_get("/me/drive", access_token)
        if r.ok:
            me_drive = self._drive(r.json())
            if me_drive not in result:
                result.insert(0, me_drive)

        return result

    @staticmethod
    def _drive(drive):
        return {
            "drive_type": DRIVES_TYPES.inverse.get(drive.get("driveType"), ""),
            "drive_id": drive["id"],
        }
