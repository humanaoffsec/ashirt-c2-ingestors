#!/usr/bin/env python3
from datetime import datetime
import hashlib
import hmac
from base64 import b64encode, b64decode, urlsafe_b64encode
from typing import Literal, Optional, TypedDict, Any, Callable
import requests
import json
from wsgiref.handlers import format_date_time
from enum import Enum, auto
import os
from dataclasses import dataclass

"""
This file was provided by Yahoo Inc. as an example for sending an API request. It has
not been modified other than to strip out unnecessary functions. Much of this code is
based on the flask_worker template in the ASHIRT Server repository.
"""

HTTP_METHOD = Literal['GET', 'POST', 'PUT', 'DELETE']

class SupportedContentType(Enum):
    HTTP_REQUEST_CYCLE = auto()
    TERMINAL_RECORDING = auto()
    CODEBLOCK = auto()
    C2EVENT = auto()
    EVENT = auto()
    IMAGE = auto()
    NONE = auto()

    @staticmethod
    def from_str(s: str):
        values: dict[str, SupportedContentType] = {
            "http-request-cycle": SupportedContentType.HTTP_REQUEST_CYCLE,
            "terminal-recording": SupportedContentType.TERMINAL_RECORDING,
            "codeblock": SupportedContentType.CODEBLOCK,
            "c2-event": SupportedContentType.C2_EVENT,
            "event": SupportedContentType.EVENT,
            "image": SupportedContentType.IMAGE,
            "none": SupportedContentType.NONE,
        }
        return values[s]

class FileData(TypedDict):
    filename: str
    mimetype: str
    content: bytes

class CreateEvidenceInput(TypedDict):
    notes: str
    content_type: Optional[SupportedContentType]
    tag_ids: Optional[list[int]]
    file: Optional[FileData]

class MultipartData(TypedDict):
    boundary: str
    data: bytes

def _random_char(length: int):
    return urlsafe_b64encode(os.urandom(length))

def encode_form(fields: dict[str, str], files: dict[str, FileData]) -> MultipartData:
    boundary = "----AShirtFormData-".encode() + _random_char(30)
    newline = "\r\n".encode()
    part = "--".encode()
    boundary_start = part + boundary + newline
    last_boundary = part + boundary + part + newline
    content_dispo = "Content-Disposition: form-data".encode()

    field_buff = bytes()
    for key, value in fields.items():
        entry = (
            boundary_start +
            content_dispo + f'; name="{key}"'.encode() +
            newline + newline +
            value.encode() +
            newline
        )
        field_buff += entry

    file_buff = bytes()
    for key, value in files.items():
        if value is None:
            continue
        entry = (
            boundary_start +
            content_dispo + f'; name="{key}"; filename="{value["filename"]}"'.encode() +
            newline + f'Content-Type: {value["mimetype"]}'.encode() +
            newline + newline +
            value['content'] +
            newline
        )
        file_buff += entry

    return {
        "boundary": boundary.decode(),
        "data": field_buff + file_buff + last_boundary
    }

def add_if_not_none(body: dict[str, Any], key: str, value: Any, tf: Callable[[Any], Any]=None):
    if value is not None:
        body.update({key: value if tf is None else tf(value)})

def now_in_rfc1123():
    """now_in_rfc1123 constructs a date like: Wed, May 11 2022 09:29:02 GMT"""
    return format_date_time(datetime.now().timestamp())

def make_hmac(
    method: HTTP_METHOD,
    path: str,
    date: str,
    body: Optional[bytes],
    access_key: str,
    secret_key: bytes
):
    """
    make_hamc builds the authentication string needed to contact ashirt.
    """
    body_digest_method = hashlib.sha256()
    if body is not None:
        try:
            body_digest_method.update(body)
        except TypeError:
            body_digest_method.update(json.dumps(body).encode())
    body_digest = body_digest_method.digest()

    to_be_hashed = f'{method}\n{path}\n{date}\n'
    full_message = to_be_hashed.encode() + body_digest

    hmacMessage = b64encode(
        hmac.new(secret_key, full_message, hashlib.sha256).digest())

    return f'{access_key}:{hmacMessage.decode("ascii")}'

@dataclass(frozen=True)
class RequestConfig:
    """
    RequestConfig abstracts a request so that it can be sent via different libraries,
    in case you don't like requests
    """
    method: HTTP_METHOD
    path: str
    body: Optional[bytes | str] = None
    return_type: Literal["json", "raw", "status", "text"] = "json"
    multipart_boundary: Optional[str] = None

RC=RequestConfig

class api_handler:
    def __init__(self, api_url: str, operation_slug: str, access_key: str, secret_key_b64: str):
        self.api_url = api_url
        self.operation_slug = operation_slug
        self.access_key = access_key
        self.secret_key = b64decode(secret_key_b64)

    def check_connection(self):
        return self.build_request(RC(method='GET', path='/api/checkconnection', return_type='json'))

    def create_evidence(self, i: CreateEvidenceInput):
        body = {
            'notes': i['notes'],
        }
        add_if_not_none(body, 'contentType', i.get('content_type'))
        add_if_not_none(body, 'tagIds', i.get('tag_ids'), json.dumps)
        
        data = encode_form(body, {"file": i.get('file')})

        return self.build_request(RC('POST',
            f'/api/operations/{self.operation_slug}/evidence',
            body=data['data'],
            multipart_boundary=data['boundary'])
            )

    def _make_request(self, cfg: RC, headers: dict[str, str], body: Optional[bytes])->bytes:
        resp = requests.request(
            cfg.method, self._route_to(cfg.path), headers=headers, data=body, stream=True)

        if cfg.return_type == 'json':
            return resp.json()
        elif cfg.return_type == 'status':
            return resp.status_code
        elif cfg.return_type == 'text':
            return resp.text

        return resp.content
    
    def _route_to(self, path: str):
        return f'{self.api_url}{path}'

    def build_request(self, cfg: RC):
        """
        build_request models a request, and the passes the request to the actual executor methods
        (_make_request)
        """
        now = now_in_rfc1123()

        # with_body should now be either bytes or None
        with_body = cfg.body.encode() if type(cfg.body) is str else cfg.body

        auth = make_hmac(cfg.method, cfg.path, now, with_body,
                         self.access_key, self.secret_key)

        if cfg.multipart_boundary is None:
            content_type = "application/json"
        else:
            content_type = f'multipart/form-data; boundary={cfg.multipart_boundary}'

        headers = {
            "Content-Type": content_type,
            "Date": now,
            "Authorization": auth,
        }

        return self._make_request(cfg, headers, with_body)
