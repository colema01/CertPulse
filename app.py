from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import base64
import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl

import webview

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec


# =============================================================
# APP PATHS
# =============================================================

BASE_DIR = Path(__file__).resolve().parent
UI_FILE = BASE_DIR / "ui" / "index.html"
LOGO_FILE = BASE_DIR / "assets" / "certpulse-logo.png"

LOCAL_APPDATA = Path(
    os.environ.get(
        "LOCALAPPDATA",
        str(Path.home() / "AppData" / "Local")
    )
)

DATA_DIR = LOCAL_APPDATA / "CertPulse"

PRIMARY_CSV = DATA_DIR / "certificates.csv"
BACKUP_CSV = DATA_DIR / "certificates.backup.csv"
TEMP_CSV = DATA_DIR / "certificates.tmp"


CSV_FIELDS = [
    "display_name",
    "ip",
    "port",
    "common_name",
    "subject",
    "issuer",
    "sans",
    "valid_from",
    "expires",
    "key_type",
    "key_size",
    "thumbprint_sha256",
    "serial_number",
    "tls_version",
    "cipher",
    "first_seen",
    "last_scanned",
    "last_successful_scan"
]


# =============================================================
# DATE HELPERS
# =============================================================

def utc_now():
    return datetime.now(timezone.utc)


def utc_now_string():
    return utc_now().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def parse_utc(value):

    if not value:
        return None

    try:

        return datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S UTC"
        ).replace(
            tzinfo=timezone.utc
        )

    except ValueError:

        return None


def days_remaining(expires_string):

    expires = parse_utc(
        expires_string
    )

    if not expires:
        return None

    seconds = (
        expires
        -
        utc_now()
    ).total_seconds()

    return int(
        seconds // 86400
    )


def status_from_days(days_left):

    if days_left is None:
        return "Unknown"

    if days_left < 0:
        return "Expired"

    if days_left <= 14:
        return "Critical"

    if days_left <= 30:
        return "Warning"

    if days_left <= 90:
        return "Upcoming"

    return "Healthy"


# =============================================================
# CERTPULSE API
# =============================================================

class CertPulseApi:

    # ---------------------------------------------------------
    # SAFE SCAN LIMITS
    # ---------------------------------------------------------

    MAX_HOSTS = 254

    MAX_PORTS = 10

    MAX_WORKERS = 4

    TCP_TIMEOUT = 2.0


    def __init__(self):

        self._ensure_storage()


    # =========================================================
    # STORAGE SETUP
    # =========================================================

    def _ensure_storage(self):

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        if not PRIMARY_CSV.exists():

            self._write_csv_atomic(
                [],
                make_backup=False
            )


    # =========================================================
    # VALIDATE INVENTORY FILE
    # =========================================================

    def _validate_csv_file(
        self,
        path
    ):

        if not path.exists():

            return False

        try:

            with path.open(
                "r",
                encoding="utf-8-sig",
                newline=""
            ) as file:

                reader = csv.DictReader(
                    file
                )

                if reader.fieldnames is None:

                    return False

                return set(
                    CSV_FIELDS
                ).issubset(
                    set(
                        reader.fieldnames
                    )
                )

        except Exception:

            return False


    # =========================================================
    # READ INVENTORY
    # =========================================================

    def _read_csv(
        self,
        path=PRIMARY_CSV
    ):

        if not self._validate_csv_file(
            path
        ):

            return []

        rows = []

        with path.open(
            "r",
            encoding="utf-8-sig",
            newline=""
        ) as file:

            reader = csv.DictReader(
                file
            )

            for row in reader:

                clean_row = {
                    field:
                        row.get(
                            field,
                            ""
                        )
                    for field
                    in CSV_FIELDS
                }

                rows.append(
                    clean_row
                )

        return rows


    # =========================================================
    # ATOMIC INVENTORY WRITE
    #
    # 1. Existing valid inventory becomes backup
    # 2. New inventory writes to temporary file
    # 3. Temporary file is validated
    # 4. Temporary file replaces primary
    #
    # This avoids partially-written inventory files.
    # =========================================================

    def _write_csv_atomic(
        self,
        rows,
        make_backup=True
    ):

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        if (
            make_backup
            and
            PRIMARY_CSV.exists()
            and
            self._validate_csv_file(
                PRIMARY_CSV
            )
        ):

            shutil.copy2(
                PRIMARY_CSV,
                BACKUP_CSV
            )

        try:

            with TEMP_CSV.open(
                "w",
                encoding="utf-8",
                newline=""
            ) as file:

                writer = csv.DictWriter(
                    file,
                    fieldnames=CSV_FIELDS
                )

                writer.writeheader()

                for row in rows:

                    writer.writerow({
                        field:
                            row.get(
                                field,
                                ""
                            )
                        for field
                        in CSV_FIELDS
                    })

            if not self._validate_csv_file(
                TEMP_CSV
            ):

                raise RuntimeError(
                    "Temporary inventory validation failed."
                )

            os.replace(
                TEMP_CSV,
                PRIMARY_CSV
            )

        finally:

            if TEMP_CSV.exists():

                try:

                    TEMP_CSV.unlink()

                except OSError:

                    pass


    # =========================================================
    # INVENTORY FOR DASHBOARD / CERTIFICATES PAGE
    # =========================================================

    def get_inventory(self):

        try:

            rows = self._read_csv()

            inventory = []

            for row in rows:

                days_left = days_remaining(
                    row["expires"]
                )

                status = status_from_days(
                    days_left
                )

                try:

                    sans = json.loads(
                        row["sans"]
                    )

                    if not isinstance(
                        sans,
                        list
                    ):

                        sans = []

                except Exception:

                    sans = []


                try:

                    port_value = int(
                        row["port"]
                    )

                except Exception:

                    port_value = row["port"]


                try:

                    key_size = (
                        int(
                            row["key_size"]
                        )
                        if row["key_size"]
                        else None
                    )

                except Exception:

                    key_size = None


                inventory.append({

                    "display_name":
                        row["display_name"],

                    "ip":
                        row["ip"],

                    "port":
                        port_value,

                    "endpoint":
                        f'{row["ip"]}:{row["port"]}',

                    "common_name":
                        row["common_name"],

                    "subject":
                        row["subject"],

                    "issuer":
                        row["issuer"],

                    "sans":
                        sans,

                    "valid_from":
                        row["valid_from"],

                    "expires":
                        row["expires"],

                    "days_left":
                        days_left,

                    "status":
                        status,

                    "key_type":
                        row["key_type"],

                    "key_size":
                        key_size,

                    "thumbprint_sha256":
                        row["thumbprint_sha256"],

                    "serial_number":
                        row["serial_number"],

                    "tls_version":
                        row["tls_version"],

                    "cipher":
                        row["cipher"],

                    "first_seen":
                        row["first_seen"],

                    "last_scanned":
                        row["last_scanned"],

                    "last_successful_scan":
                        row["last_successful_scan"]

                })


            inventory.sort(
                key=lambda item: (
                    int(
                        ipaddress.ip_address(
                            item["ip"]
                        )
                    ),
                    int(
                        item["port"]
                    )
                )
            )


            summary = self._build_summary(
                inventory
            )


            return {

                "ok": True,

                "inventory":
                    inventory,

                "summary":
                    summary

            }


        except Exception as exc:

            return {

                "ok": False,

                "message":
                    f"Could not load inventory: {exc}"

            }


    # =========================================================
    # DASHBOARD SUMMARY
    # =========================================================

    def _build_summary(
        self,
        inventory
    ):

        summary = {

            "monitored":
                len(
                    inventory
                ),

            "healthy":
                0,

            "upcoming":
                0,

            "warning":
                0,

            "critical":
                0,

            "expired":
                0

        }


        for cert in inventory:

            status = cert[
                "status"
            ]


            if status == "Healthy":

                summary[
                    "healthy"
                ] += 1


            elif status == "Upcoming":

                summary[
                    "upcoming"
                ] += 1


            elif status == "Warning":

                summary[
                    "warning"
                ] += 1


            elif status == "Critical":

                summary[
                    "critical"
                ] += 1


            elif status == "Expired":

                summary[
                    "expired"
                ] += 1


        summary["due_90"] = (

            summary["upcoming"]

            +

            summary["warning"]

            +

            summary["critical"]

            +

            summary["expired"]

        )


        summary["due_30"] = (

            summary["warning"]

            +

            summary["critical"]

            +

            summary["expired"]

        )


        return summary



    # =========================================================
    # RESCAN ONE CERTIFICATE
    # =========================================================

    def rescan_certificate(
        self,
        ip,
        port
    ):

        try:

            parsed_ip = ipaddress.ip_address(
                str(
                    ip
                ).strip()
            )

            if parsed_ip.version != 4:

                return {
                    "ok": False,
                    "message": "Invalid certificate IP."
                }

            parsed_port = int(
                port
            )

            if (
                parsed_port < 1
                or
                parsed_port > 65535
            ):

                return {
                    "ok": False,
                    "message": "Invalid certificate port."
                }

            result = self._fetch_certificate(
                str(
                    parsed_ip
                ),
                parsed_port
            )

            if not result.get(
                "ok"
            ):

                return {
                    "ok": False,
                    "message":
                        result.get(
                            "message",
                            "Certificate rescan failed."
                        ),
                    "endpoint":
                        f"{parsed_ip}:{parsed_port}"
                }

            save_result = self._merge_scan_results(
                [
                    result
                ]
            )

            if not save_result.get(
                "ok"
            ):

                return {
                    "ok": False,
                    "message":
                        save_result.get(
                            "message",
                            "Inventory update failed."
                        )
                }

            return {
                "ok": True,
                "message":
                    "Certificate rescanned successfully.",
                "certificate":
                    result,
                "new_records":
                    save_result.get(
                        "new_records",
                        0
                    ),
                "updated_records":
                    save_result.get(
                        "updated_records",
                        0
                    )
            }

        except Exception as exc:

            return {
                "ok": False,
                "message":
                    f"Could not rescan certificate: {exc}"
            }


    # =========================================================
    # DELETE CERTIFICATE FROM LOCAL INVENTORY
    #
    # This only removes the IP + port entry from CertPulse's
    # local CSV inventory. It makes no connection to the remote
    # endpoint and changes nothing on the remote system.
    # =========================================================

    def delete_certificate(
        self,
        ip,
        port
    ):

        try:

            parsed_ip = ipaddress.ip_address(
                str(
                    ip
                ).strip()
            )


            if parsed_ip.version != 4:

                return {

                    "ok":
                        False,

                    "message":
                        "Invalid certificate IP."

                }


            parsed_port = int(
                port
            )


            if (
                parsed_port < 1
                or
                parsed_port > 65535
            ):

                return {

                    "ok":
                        False,

                    "message":
                        "Invalid certificate port."

                }


            rows = self._read_csv()


            original_count = len(
                rows
            )


            remaining_rows = [

                row

                for row in rows

                if not (

                    row["ip"]
                    ==
                    str(
                        parsed_ip
                    )

                    and

                    str(
                        row["port"]
                    )
                    ==
                    str(
                        parsed_port
                    )

                )

            ]


            if len(
                remaining_rows
            ) == original_count:

                return {

                    "ok":
                        False,

                    "message":
                        "Certificate entry was not found."

                }


            # The current primary inventory becomes the single
            # rolling backup before the deletion is committed.

            self._write_csv_atomic(
                remaining_rows,
                make_backup=True
            )


            return {

                "ok":
                    True,

                "message":
                    "Certificate removed from CertPulse inventory."

            }


        except Exception as exc:

            return {

                "ok":
                    False,

                "message":
                    f"Could not delete certificate: {exc}"

            }


    # =========================================================
    # BACKUP INFORMATION
    # =========================================================

    def get_backup_info(self):

        if not BACKUP_CSV.exists():

            return {

                "ok": True,

                "available":
                    False

            }


        if not self._validate_csv_file(
            BACKUP_CSV
        ):

            return {

                "ok": True,

                "available":
                    False,

                "message":
                    "Backup exists but is not valid."

            }


        rows = self._read_csv(
            BACKUP_CSV
        )


        modified = datetime.fromtimestamp(
            BACKUP_CSV.stat().st_mtime,
            tz=timezone.utc
        )


        return {

            "ok":
                True,

            "available":
                True,

            "records":
                len(
                    rows
                ),

            "created":
                modified.strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )

        }


    # =========================================================
    # RESTORE BACKUP
    # =========================================================

    def restore_backup(self):

        try:

            if not BACKUP_CSV.exists():

                return {

                    "ok":
                        False,

                    "message":
                        "No backup is available."

                }


            if not self._validate_csv_file(
                BACKUP_CSV
            ):

                return {

                    "ok":
                        False,

                    "message":
                        "The backup file is not valid."

                }


            shutil.copy2(
                BACKUP_CSV,
                TEMP_CSV
            )


            if not self._validate_csv_file(
                TEMP_CSV
            ):

                raise RuntimeError(
                    "Backup validation failed."
                )


            os.replace(
                TEMP_CSV,
                PRIMARY_CSV
            )


            return {

                "ok":
                    True,

                "message":
                    "Backup restored successfully."

            }


        except Exception as exc:

            return {

                "ok":
                    False,

                "message":
                    f"Backup restore failed: {exc}"

            }


        finally:

            if TEMP_CSV.exists():

                try:

                    TEMP_CSV.unlink()

                except OSError:

                    pass


    # =========================================================
    # VALIDATE SCAN
    # =========================================================

    def validate_scan(
        self,
        target,
        ports
    ):

        try:

            targets = self._parse_target(
                target
            )

            parsed_ports = self._parse_ports(
                ports
            )


            return {

                "ok":
                    True,

                "host_count":
                    len(
                        targets
                    ),

                "ports":
                    parsed_ports,

                "connection_count":
                    len(
                        targets
                    )
                    *
                    len(
                        parsed_ports
                    ),

                "normalized_target":
                    target.strip(),

                "concurrency":
                    self.MAX_WORKERS,

                "retries":
                    0

            }


        except ValueError as exc:

            return {

                "ok":
                    False,

                "message":
                    str(
                        exc
                    )

            }


    # =========================================================
    # SCAN CERTIFICATES
    # =========================================================

    def scan_certificates(
        self,
        target,
        ports
    ):

        try:

            targets = self._parse_target(
                target
            )

            parsed_ports = self._parse_ports(
                ports
            )


        except ValueError as exc:

            return {

                "ok":
                    False,

                "message":
                    str(
                        exc
                    )

            }


        jobs = [

            (
                ip,
                port
            )

            for ip in targets

            for port in parsed_ports

        ]


        successful = []

        failed = []


        # -----------------------------------------------------
        # IMPORTANT:
        #
        # CertPulse never creates more than 4 worker threads.
        # This is intentional to keep scans low impact.
        # -----------------------------------------------------

        with ThreadPoolExecutor(
            max_workers=
                self.MAX_WORKERS
        ) as executor:


            future_map = {

                executor.submit(
                    self._fetch_certificate,
                    ip,
                    port
                ):
                (
                    ip,
                    port
                )

                for ip, port in jobs

            }


            for future in as_completed(
                future_map
            ):


                ip, port = future_map[
                    future
                ]


                try:

                    result = future.result()


                except Exception as exc:

                    result = {

                        "ok":
                            False,

                        "ip":
                            ip,

                        "port":
                            port,

                        "endpoint":
                            f"{ip}:{port}",

                        "message":
                            f"Unexpected error: {exc}"

                    }


                if result.get(
                    "ok"
                ):

                    successful.append(
                        result
                    )


                else:

                    failed.append(
                        result
                    )


        successful.sort(
            key=lambda item: (

                int(
                    ipaddress.ip_address(
                        item["ip"]
                    )
                ),

                item["port"]

            )
        )


        save_result = self._merge_scan_results(
            successful
        )


        if not save_result[
            "ok"
        ]:

            return {

                "ok":
                    False,

                "message":
                    save_result[
                        "message"
                    ]

            }


        return {

            "ok":
                True,

            "target":
                target.strip(),

            "ports":
                parsed_ports,

            "host_count":
                len(
                    targets
                ),

            "attempted":
                len(
                    jobs
                ),

            "found":
                len(
                    successful
                ),

            "failed":
                len(
                    failed
                ),

            "concurrency":
                self.MAX_WORKERS,

            "retries":
                0,

            "results":
                successful,

            "saved":
                save_result[
                    "saved"
                ],

            "new_records":
                save_result[
                    "new_records"
                ],

            "updated_records":
                save_result[
                    "updated_records"
                ]

        }


    # =========================================================
    # MERGE SCAN RESULTS INTO INVENTORY
    # =========================================================

    def _merge_scan_results(
        self,
        successful
    ):

        try:

            existing = self._read_csv()

            by_endpoint = {

                (
                    row["ip"],
                    str(
                        row["port"]
                    )
                ):
                row

                for row in existing

            }


            now_string = utc_now_string()


            new_records = 0

            updated_records = 0


            for cert in successful:


                key = (

                    cert["ip"],

                    str(
                        cert["port"]
                    )

                )


                existing_row = by_endpoint.get(
                    key
                )


                if existing_row:


                    display_name = (

                        existing_row[
                            "display_name"
                        ]

                        or

                        cert[
                            "common_name"
                        ]

                        or

                        cert[
                            "endpoint"
                        ]

                    )


                    first_seen = (

                        existing_row[
                            "first_seen"
                        ]

                        or

                        now_string

                    )


                    updated_records += 1


                else:


                    display_name = (

                        cert[
                            "common_name"
                        ]

                        or

                        cert[
                            "endpoint"
                        ]

                    )


                    first_seen = (
                        now_string
                    )


                    new_records += 1


                by_endpoint[
                    key
                ] = {


                    "display_name":
                        display_name,


                    "ip":
                        cert[
                            "ip"
                        ],


                    "port":
                        str(
                            cert[
                                "port"
                            ]
                        ),


                    "common_name":
                        cert[
                            "common_name"
                        ],


                    "subject":
                        cert[
                            "subject"
                        ],


                    "issuer":
                        cert[
                            "issuer"
                        ],


                    "sans":
                        json.dumps(
                            cert[
                                "sans"
                            ]
                        ),


                    "valid_from":
                        cert[
                            "valid_from"
                        ],


                    "expires":
                        cert[
                            "expires"
                        ],


                    "key_type":
                        cert[
                            "key_type"
                        ],


                    "key_size":
                        str(
                            cert[
                                "key_size"
                            ]
                            or
                            ""
                        ),


                    "thumbprint_sha256":
                        cert[
                            "thumbprint_sha256"
                        ],


                    "serial_number":
                        cert[
                            "serial_number"
                        ],


                    "tls_version":
                        cert[
                            "tls_version"
                        ],


                    "cipher":
                        cert[
                            "cipher"
                        ],


                    "first_seen":
                        first_seen,


                    "last_scanned":
                        now_string,


                    "last_successful_scan":
                        now_string

                }


            merged = list(
                by_endpoint.values()
            )


            merged.sort(
                key=lambda row: (

                    int(
                        ipaddress.ip_address(
                            row["ip"]
                        )
                    ),

                    int(
                        row["port"]
                    )

                )
            )


            if successful:

                self._write_csv_atomic(
                    merged,
                    make_backup=True
                )


            return {

                "ok":
                    True,

                "saved":
                    len(
                        successful
                    ),

                "new_records":
                    new_records,

                "updated_records":
                    updated_records

            }


        except Exception as exc:

            return {

                "ok":
                    False,

                "message":
                    f"Inventory save failed: {exc}"

            }


    # =========================================================
    # FETCH TLS CERTIFICATE
    # =========================================================

    def _fetch_certificate(
        self,
        target,
        port
    ):

        endpoint = (
            f"{target}:{port}"
        )


        try:

            # -------------------------------------------------
            # CERTIFICATE INSPECTION CONTEXT
            #
            # We intentionally do not validate trust here.
            #
            # CertPulse is inspecting what certificate the
            # endpoint presents. This allows it to discover:
            #
            # - internal CA certificates
            # - self-signed certificates
            # - expired certificates
            # - otherwise untrusted certificates
            #
            # This does NOT modify the remote host.
            # -------------------------------------------------

            context = ssl.SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            )

            context.check_hostname = False

            context.verify_mode = (
                ssl.CERT_NONE
            )


            with socket.create_connection(
                (
                    target,
                    port
                ),
                timeout=
                    self.TCP_TIMEOUT
            ) as tcp_socket:


                with context.wrap_socket(
                    tcp_socket,
                    server_hostname=None
                ) as tls_socket:


                    der_cert = (
                        tls_socket.getpeercert(
                            binary_form=True
                        )
                    )


                    if not der_cert:

                        return {

                            "ok":
                                False,

                            "ip":
                                target,

                            "port":
                                port,

                            "endpoint":
                                endpoint,

                            "message":
                                "No certificate returned."

                        }


                    tls_version = (

                        tls_socket.version()

                        or

                        "Unknown"

                    )


                    cipher_info = (
                        tls_socket.cipher()
                    )


            cert = (
                x509.load_der_x509_certificate(
                    der_cert
                )
            )


            subject = (
                cert.subject
                .rfc4514_string()
            )


            issuer = (
                cert.issuer
                .rfc4514_string()
            )


            # -------------------------------------------------
            # COMMON NAME
            # -------------------------------------------------

            common_name = ""


            try:

                cn_values = (

                    cert.subject

                    .get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME
                    )

                )


                if cn_values:

                    common_name = (
                        cn_values[0].value
                    )


            except Exception:

                common_name = ""


            # -------------------------------------------------
            # SUBJECT ALTERNATIVE NAMES
            # -------------------------------------------------

            san_names = []


            try:

                san_extension = (

                    cert.extensions

                    .get_extension_for_class(
                        x509.SubjectAlternativeName
                    )

                )


                san_names = (

                    san_extension.value

                    .get_values_for_type(
                        x509.DNSName
                    )

                )


            except x509.ExtensionNotFound:

                san_names = []


            # -------------------------------------------------
            # VALIDITY
            # -------------------------------------------------

            valid_from = (
                cert.not_valid_before_utc
            )


            expires = (
                cert.not_valid_after_utc
            )


            seconds_left = (

                expires

                -

                utc_now()

            ).total_seconds()


            days_left = int(
                seconds_left // 86400
            )


            # -------------------------------------------------
            # PUBLIC KEY
            # -------------------------------------------------

            public_key = (
                cert.public_key()
            )


            key_type = "Unknown"

            key_size = None


            if isinstance(
                public_key,
                rsa.RSAPublicKey
            ):

                key_type = "RSA"

                key_size = (
                    public_key.key_size
                )


            elif isinstance(
                public_key,
                ec.EllipticCurvePublicKey
            ):

                key_type = "EC"

                key_size = (
                    public_key.key_size
                )


            # -------------------------------------------------
            # SHA-256 THUMBPRINT
            # -------------------------------------------------

            fingerprint = (

                hashlib.sha256(
                    der_cert
                )

                .hexdigest()

                .upper()

            )


            thumbprint = ":".join(

                fingerprint[
                    i:i + 2
                ]

                for i in range(
                    0,
                    len(
                        fingerprint
                    ),
                    2
                )

            )


            cipher_name = (

                cipher_info[0]

                if cipher_info

                else

                "Unknown"

            )


            return {


                "ok":
                    True,


                "ip":
                    target,


                "port":
                    port,


                "endpoint":
                    endpoint,


                "common_name":
                    common_name,


                "subject":
                    subject,


                "issuer":
                    issuer,


                "sans":
                    san_names,


                "valid_from":
                    valid_from.strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),


                "expires":
                    expires.strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),


                "days_left":
                    days_left,


                "status":
                    status_from_days(
                        days_left
                    ),


                "key_type":
                    key_type,


                "key_size":
                    key_size,


                "thumbprint_sha256":
                    thumbprint,


                "serial_number":
                    format(
                        cert.serial_number,
                        "X"
                    ),


                "tls_version":
                    tls_version,


                "cipher":
                    cipher_name

            }


        except socket.timeout:

            return {

                "ok":
                    False,

                "ip":
                    target,

                "port":
                    port,

                "endpoint":
                    endpoint,

                "message":
                    "Connection timed out."

            }


        except ConnectionRefusedError:

            return {

                "ok":
                    False,

                "ip":
                    target,

                "port":
                    port,

                "endpoint":
                    endpoint,

                "message":
                    "Connection refused."

            }


        except ssl.SSLError:

            return {

                "ok":
                    False,

                "ip":
                    target,

                "port":
                    port,

                "endpoint":
                    endpoint,

                "message":
                    "No usable TLS certificate."

            }


        except OSError:

            return {

                "ok":
                    False,

                "ip":
                    target,

                "port":
                    port,

                "endpoint":
                    endpoint,

                "message":
                    "Connection unavailable."

            }


        except Exception as exc:

            return {

                "ok":
                    False,

                "ip":
                    target,

                "port":
                    port,

                "endpoint":
                    endpoint,

                "message":
                    f"Unexpected error: {exc}"

            }


    # =========================================================
    # TARGET PARSER
    # =========================================================

    def _parse_target(
        self,
        value
    ):

        value = value.strip()


        if not value:

            raise ValueError(
                "Enter an IP address, range, or CIDR."
            )

        if "/" in value:

            try:

                network = (
                    ipaddress.ip_network(
                        value,
                        strict=False
                    )
                )


            except ValueError:

                raise ValueError(
                    "Invalid CIDR network."
                )


            if network.version != 4:

                raise ValueError(
                    "CertPulse currently supports IPv4 only."
                )


            hosts = list(
                network.hosts()
            )


            # A /32 is one specific host.

            if network.prefixlen == 32:

                hosts = [
                    network.network_address
                ]


            if len(
                hosts
            ) > self.MAX_HOSTS:

                raise ValueError(
                    "Safe Scan Mode currently limits "
                    "a scan to 254 hosts."
                )


            return [

                str(
                    ip
                )

                for ip in hosts

            ]

        if "-" in value:

            parts = value.split(
                "-"
            )


            if len(
                parts
            ) != 2:

                raise ValueError(
                    "Invalid IP range."
                )


            try:

                start = (
                    ipaddress.ip_address(
                        parts[0].strip()
                    )
                )


                end = (
                    ipaddress.ip_address(
                        parts[1].strip()
                    )
                )


            except ValueError:

                raise ValueError(
                    "Invalid IP address in range."
                )


            if (
                start.version != 4
                or
                end.version != 4
            ):

                raise ValueError(
                    "CertPulse currently supports IPv4 only."
                )


            if int(
                end
            ) < int(
                start
            ):

                raise ValueError(
                    "Ending IP must be greater than "
                    "or equal to starting IP."
                )


            count = (

                int(
                    end
                )

                -

                int(
                    start
                )

                +

                1

            )


            if count > self.MAX_HOSTS:

                raise ValueError(
                    "Safe Scan Mode currently limits "
                    "a scan to 254 hosts."
                )


            return [

                str(
                    ipaddress.ip_address(
                        int(
                            start
                        )
                        +
                        offset
                    )
                )

                for offset
                in range(
                    count
                )

            ]


        # -----------------------------------------------------
        # SINGLE IP
        # -----------------------------------------------------

        try:

            ip = (
                ipaddress.ip_address(
                    value
                )
            )


        except ValueError:

            raise ValueError(
                "Invalid IP address."
            )


        if ip.version != 4:

            raise ValueError(
                "CertPulse currently supports IPv4 only."
            )


        return [
            str(
                ip
            )
        ]


    # =========================================================
    # PORT PARSER
    # =========================================================

    def _parse_ports(
        self,
        value
    ):

        value = value.strip()


        if not value:

            raise ValueError(
                "Enter at least one port."
            )


        raw_ports = [

            item.strip()

            for item in value.split(
                ","
            )

            if item.strip()

        ]


        ports = []


        for item in raw_ports:


            if not re.fullmatch(
                r"\d+",
                item
            ):

                raise ValueError(
                    f"Invalid port: {item}"
                )


            port = int(
                item
            )


            if (
                port < 1
                or
                port > 65535
            ):

                raise ValueError(
                    f"Port {port} is outside "
                    "the valid range 1-65535."
                )


            if port not in ports:

                ports.append(
                    port
                )


        if len(
            ports
        ) > self.MAX_PORTS:

            raise ValueError(
                "CertPulse currently allows "
                "a maximum of 10 ports per scan."
            )


        return ports


# =============================================================
# LOAD UI
# =============================================================

html = UI_FILE.read_text(
    encoding="utf-8"
)


# =============================================================
# EMBED LOGO INTO THE LOCAL PAGE
# =============================================================

if LOGO_FILE.exists():

    encoded_logo = (

        base64.b64encode(
            LOGO_FILE.read_bytes()
        )

        .decode(
            "utf-8"
        )

    )


    logo_uri = (

        "data:image/png;base64,"

        +

        encoded_logo

    )


    html = html.replace(
        "__CERTPULSE_LOGO__",
        logo_uri
    )


else:

    html = html.replace(
        "__CERTPULSE_LOGO__",
        ""
    )


# =============================================================
# START CERTPULSE
# =============================================================

api = CertPulseApi()


webview.create_window(

    "CertPulse",

    html=html,

    js_api=api,

    width=1500,

    height=950,

    min_size=(
        1100,
        700
    ),

    background_color=
        "#080d13"

)


webview.start(

    gui="edgechromium",

    debug=False

)
