#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# --- Constants and Definitions ---

ConditionKey = tuple[str, str, str, str, str]
RunRecord = Mapping[str, Any]

PROFILE_ORDER = [
    "rsa_pss",
    "eddsa",
    "ecdsa",
    "hmac_sha256",
    "ml_dsa",
    "slh_dsa",
    "fn_dsa",
    "rsa_pss_ml_dsa",
]
CLASSICAL_PROFILES = {"rsa_pss", "eddsa", "ecdsa", "hmac_sha256"}
PQC_PROFILES = {"ml_dsa", "slh_dsa", "fn_dsa"}
HYBRID_PROFILES = {"rsa_pss_ml_dsa"}
HASH_ORDER = ["sha256", "blake3", "keccak256"]
SCENARIO_ORDER = [
    "workflow",
    "sign_only",
    "verify_manifest",
    "verify_stored",
    "verify_uploaded",
    "verify_full",
]
STORAGE_STATE_ORDER = ["cold", "warm"]
SUMMARY_FIELD_BY_RAW_METRIC = {
    "setup_upload_ms": "setup_upload_ms",
    "setup_process_ms": "setup_process_ms",
    "client_upload_ms": "upload_ms",
    "client_process_ms": "process_ms",
    "client_verify_ms": "verify_ms",
    "client_total_ms": "total_ms",
    "client_upload_mib_s": "client_upload_mib_s",
    "client_process_mib_s": "client_process_mib_s",
    "client_verify_mib_s": "client_verify_mib_s",
    "client_total_mib_s": "client_total_mib_s",
    "server_process_gateway_ms": "server_process_gateway_ms",
    "server_verify_gateway_ms": "server_verify_gateway_ms",
    "server_hash_ms": "server_hash_ms",
    "server_object_exists_check_ms": "server_object_exists_check_ms",
    "server_object_store_ms": "server_object_store_ms",
    "server_manifest_canonicalize_ms": "server_manifest_canonicalize_ms",
    "server_db_persist_ms": "server_db_persist_ms",
    "server_rsa_sign_ms": "server_rsa_sign_ms",
    "server_ml_dsa_sign_ms": "server_ml_dsa_sign_ms",
    "server_eddsa_sign_ms": "server_eddsa_sign_ms",
    "server_ecdsa_sign_ms": "server_ecdsa_sign_ms",
    "server_hmac_sign_ms": "server_hmac_sign_ms",
    "server_ml_dsa_sign_ms": "server_ml_dsa_sign_ms",
    "server_slh_dsa_sign_ms": "server_slh_dsa_sign_ms",
    "server_fn_dsa_sign_ms": "server_fn_dsa_sign_ms",
    "server_eddsa_verify_ms": "server_eddsa_verify_ms",
    "server_ecdsa_verify_ms": "server_ecdsa_verify_ms",
    "server_hmac_verify_ms": "server_hmac_verify_ms",
    "server_ml_dsa_verify_ms": "server_ml_dsa_verify_ms",
    "server_slh_dsa_verify_ms": "server_slh_dsa_verify_ms",
    "server_fn_dsa_verify_ms": "server_fn_dsa_verify_ms",
    "server_manifest_fetch_db_lookup_ms": "server_manifest_fetch_db_lookup_ms",
    "server_verify_hash_ms": "server_verify_hash_ms",
    "server_verify_canonicalize_ms": "server_verify_canonicalize_ms",
    "server_signature_verify_ms": "server_signature_verify_ms",
    "server_stored_object_verify_ms": "server_stored_object_verify_ms",
    "server_uploaded_content_verify_ms": "server_uploaded_content_verify_ms",
    "server_verify_ms": "server_verify_ms",
    "server_total_ms": "server_total_ms",
    "server_hash_mib_s": "server_hash_mib_s",
    "server_verify_mib_s": "server_verify_mib_s",
    "server_total_mib_s": "server_total_mib_s",
    "manifest_size_bytes": "manifest_size_bytes",
    "manifest_core_bytes": "manifest_core_bytes",
    "manifest_core_cbor_bytes": "manifest_core_cbor_bytes",
    "manifest_envelope_bytes": "manifest_envelope_bytes",
    "rsa_signature_bytes": "rsa_signature_bytes",
    "ml_dsa_signature_bytes": "ml_dsa_signature_bytes",
    "eddsa_signature_bytes": "eddsa_signature_bytes",
    "ecdsa_signature_bytes": "ecdsa_signature_bytes",
    "hmac_signature_bytes": "hmac_signature_bytes",
    "ml_dsa_signature_bytes": "ml_dsa_signature_bytes",
    "slh_dsa_signature_bytes": "slh_dsa_signature_bytes",
    "fn_dsa_signature_bytes": "fn_dsa_signature_bytes",
    "total_signature_bytes": "total_signature_bytes",
}

# --- Helper Functions ---

def get_avg_duration(data):
    return f"{data:.2f} seconds"

# --- Main Logic ---

def analyze_results(results):
    print("\n" + "="*80)
    print("================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================