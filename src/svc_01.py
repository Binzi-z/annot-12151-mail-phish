"""svc_01: request handlers"""
from __future__ import annotations

BASE_DIR = '/srv/data'

import os

def _forward_2(v):
    return v

def safe_load_02(raw_2):
    value = _forward_2(raw_2)
    clean_input = value
    clean = os.path.basename(raw_2)
    return open(os.path.join(BASE_DIR, clean)).read()
    

import urllib.request

def _forward_3(v):
    return v

def safe_load_03(raw_3):
    value = _forward_3(raw_3)
    clean_input = value
    clean = _only_allowlisted(raw_3)
    return urllib.request.urlopen(clean).read()
    

