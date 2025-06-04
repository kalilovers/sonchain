#!/usr/bin/env python3

# -*- coding: utf-8 -*-

# src/src_psiphon.py

#src_ > >>>
from src import src_menus
from src import src_utils
from src import src_remover
from src import src_installer
from src import src_status

#modules >
import os
import sys
import json
import shutil
import subprocess
import re
import time
import uuid
from pathlib import Path


PSIPHON_BINARY = "/opt/psiphon/psiphon-tunnel-core"
CONFIG_DIR = "/etc/psiphon"
CONFIG_FILE = f"{CONFIG_DIR}/psiphon.conf"
SERVICE_PATH = "/etc/systemd/system/psiphon.service"
SERVICE_NAME = "psiphon.service"
LOG_PATH = "/opt/psiphon/ca.psiphon.PsiphonTunnel.tunnel-core/notices"
PSIPHON_DOWNLOAD_URL_X86_64 = "https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/raw/master/linux/psiphon-tunnel-core-x86_64"


default_config = {
    "PropagationChannelId": "FFFFFFFFFFFFFFFF",
    "SponsorId": "FFFFFFFFFFFFFFFF",
    "RemoteServerListDownloadFilename": "remote_server_list",
    "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
    "RemoteServerListUrl": "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
    "DataRootDirectory": "/opt/psiphon",
    "LocalHttpProxyPort": 8081,
    "LocalSocksProxyPort": 1081,
    "EgressRegion": "",
    "DeviceRegion": "",
    "ConnectionWorkerPoolSize": 40,
    "StaggerConnectionWorkersMilliseconds": 150,
    "NetworkLatencyMultiplier": 1.0,
    "TunnelPoolSize": 2,
    "EmitDiagnosticNotices": True,
    "UseNoticeFiles": {
        "MaxSizeBytes": 51200,
        "MaxRotateCount": 1
    }
}


REGIONS = {
    "1": "US",
    "2": "CA",
    "3": "GB",
    "4": "DE",
    "5": "FR",
    "6": "NL",
    "7": "IT",
    "8": "ES",
    "9": "CH",
    "10": "SE",
    "11": "NO",
    "12": "FI",
    "13": "JP",
    "14": "SG",
    "15": "AU",
    "16": "IN",
    "17": "HK",
    "18": "BR",
    "19": "AR",
    "20": "AT",
    "21": "BE",
    "22": "BG",
    "23": "CZ",
    "24": "DK",
    "25": "GR",
    "26": "HR",
    "27": "ID",
    "28": "IE",
    "29": "PL",
    "30": "PT",
    "31": "RO",
    "32": "RS",
    "33": "SK",
    "34": "UA"
}


tunnelprotocols = {
    "1": "SSH",
    "2": "OSSH",
    "3": "QUIC-OSSH",
    "4": "TLS-OSSH",
    "5": "SHADOWSOCKS-OSSH",
    "6": "UNFRONTED-MEEK-OSSH",
    "7": "FRONTED-MEEK-OSSH",
    "8": "UNFRONTED-MEEK-HTTPS-OSSH"
}


PARAMETER_RULES = {
    "LocalHttpProxyPort": {"type": int, "range": (0, 65535)},
    "LocalSocksProxyPort": {"type": int, "range": (0, 65535)},
    "EmitDiagnosticNotices": {"type": bool},
    "EmitDiagnosticNetworkParameters": {"type": bool},
    "SplitTunnelOwnRegion": {"type": bool},
    "LimitRelayBufferSizes": {"type": bool},

    "EgressRegion": {"type": str, "length": 2, "uppercase": True, "allow_empty": True},
    "DeviceRegion": {"type": str, "length": 2, "uppercase": True, "allow_empty": True},
    "SplitTunnelRegions": {"type": list, "uppercase_all": True},

    "LimitTunnelProtocols": {
        "type": list,
        "allowed_values": [
            "SSH", "OSSH", "QUIC-OSSH", "TLS-OSSH",
            "SHADOWSOCKS-OSSH", "UNFRONTED-MEEK-OSSH",
            "FRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH"
        ],
        "uppercase_all": True
    },

    "DataRootDirectory": {"type": str, "min_length": 1, "allow_empty": False},
    "UpstreamProxyURL": {"type": str},

    "RemoteServerListUrl": {"type": str, "startswith": "https"},
    "RemoteServerListDownloadFilename": {"type": str},
    "RemoteServerListSignaturePublicKey": {"type": str, "min_length": 10},
    "SponsorId": {"type": str, "min_length": 1, "allow_empty": False},
    "PropagationChannelId": {"type": str, "min_length": 1, "allow_empty": False},

    "ConnectionWorkerPoolSize": {"type": int},
    "TunnelPoolSize": {"type": int},
    "StaggerConnectionWorkersMilliseconds": {"type": int},
    "EstablishTunnelPausePeriodSeconds": {"type": int},
    "NetworkLatencyMultiplier": {"type": float},

    "UseNoticeFiles": {"type": dict},
}



#======================================================================#
#======================================================================#
#================================DEFs:=================================#
#======================================================================#
#======================================================================#


def get_parameter_help(key):
    # Structured help entries
    PARAMETER_HELPS = {
        "LocalHttpProxyPort": {
            "description": "The local port number on which Psiphon will listen for HTTP proxy connections.",
            "examples": [
                "8080",
                "3128"
            ],
            "notes": [
                "Set to 0 to disable local HTTP proxy.",
                "Ensure port is not blocked by firewall or used by another app."
            ]
        },
        "LocalSocksProxyPort": {
            "description": "The local port number on which Psiphon will listen for SOCKS proxy connections.",
            "examples": [
                "1080",
                "1081"
            ],
            "notes": [
                "Set to 0 to disable local SOCKS proxy.",
                "Useful for apps that require SOCKS5 (e.g., browsers, torrent clients)"
            ]
        },
        "EmitDiagnosticNotices": {
            "description": "Indicates whether to output notices containing detailed information about the Psiphon session.",
            "examples": [
                "true   # Enable detailed diagnostic logs",
                "false  # Disable logs for reduced overhead"
            ],
            "notes": [
                "These notices may contain sensitive information.",
                "Should not be insecurely distributed or displayed to users.",
                "Default is off."
            ]
        },
        "EmitDiagnosticNetworkParameters": {
            "description": "Indicates whether to include network parameters in diagnostic notices.",
            "examples": [
                "true   # Include advanced network metrics",
                "false  # Minimal diagnostic output"
            ],
            "notes": [
                "These parameters are sensitive circumvention network information.",
                "Should not be insecurely distributed or displayed to users.",
                "Default is off."
            ]
        },
        "SplitTunnelOwnRegion": {
            "description": "When enabled, TCP port forward destinations that resolve to the same GeoIP country as the client are connected to directly, untunneled.",
            "examples": [
                "true   # Exclude local region traffic from tunnel",
                "false  # Tunnel all TCP port forward traffic"
            ],
            "notes": [
                "This option is enabled when SplitTunnelOwnRegion is true."
            ]
        },
        "DataRootDirectory": {
            "description": "The directory in which to store persistent files, which contain information such as server entries. By default, current working directory.",
            "examples": [
                "/var/lib/psiphon"
            ],
            "notes": [
                "Psiphon assumes full control of files under this directory. They may be deleted, moved, or overwritten."
            ]
        },
        "UpstreamProxyURL": {
            "description": "A URL specifying an upstream proxy to use for all outbound connections. The URL should include proxy type and authentication information, as required.",
            "examples": [
                "http://proxy.example.com:8080",
                "socks5://user:pass@127.0.0.1:1080"
            ],
            "notes": [
                "See example URLs here: https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/master/psiphon/upstreamproxy" 
            ]
        },
        "RemoteServerListDownloadFilename": {
            "description": "[Deprecated] Target filename for remote server list download. Data is stored in co-located files (e.g., RemoteServerListDownloadFilename.part*).",
            "examples": [
                "servers_list.json",
                "psiphon_remote_list.dat"
            ],
            "notes": [
                "[Deprecated] Use MigrateRemoteServerListDownloadFilename instead."
            ]
        },
        "RemoteServerListSignaturePublicKey": {
            "description": "A base64-encoded, RSA public key used to authenticate the remote server list payload.",
            "examples": [
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...",
                "Base64-encoded RSA public key"
            ],
            "notes": [
                "This value is supplied by and depends on the Psiphon Network."
            ]
        },
        "SponsorId": {
            "description": "A string identifier which indicates who is sponsoring this Psiphon client. One purpose of this value is to determine the home pages for display.",
            "examples": [
                "sponsor_12345",
                "partner_alpha"
            ],
            "notes": [
                "This value is supplied by and depends on the Psiphon Network, and is typically embedded in the client binary."
            ]
        },
        "PropagationChannelId": {
            "description": "A string identifier which indicates how the Psiphon client was distributed. This parameter is required.",
            "examples": [
                "channel_beta",
                "android_googleplay"
            ],
            "notes": [
                "This value is supplied by and depends on the Psiphon Network.",
                "Typically embedded in the client binary."
            ]
        },
        "UseNoticeFiles": {
            "description": "Configures notice files for writing. If set, homepages will be written to a file created at config.GetHomePageFilename() and notices will be written to a file created at config.GetNoticesFilename().",
            "examples": [
                "1024  # File rotation size (in bytes)",
                "2048  # Larger file size before rotation"
            ],
            "notes": [
                "The value sets the size and frequency at which the notices file will be rotated.",
                "One rotated older file (config.GetOldNoticesFilename()) is retained.",
                "Diagnostic notices are omitted from the notice files."
            ]
        },
        "ConnectionWorkerPoolSize": {
            "description": "Specifies how many connection attempts to attempt in parallel. If omitted or when 0, a default is used.",
            "examples": [
                "10  # lower concurrency",
                "50  # typical value",
                "100 # high concurrency"
            ],
            "notes": [
                "Too many workers can cause resource contention.",
                "Values above 200 may not provide significant benefits."
            ]
        },
        "TunnelPoolSize": {
            "description": "Specifies how many tunnels to run in parallel. Port forwards are multiplexed over multiple tunnels. 0 uses the default value.",
            "examples": [
                "2   # minimal redundancy",
                "4   # default value",
                "8   # higher availability"
            ],
            "notes": [
                "Values over MAX_TUNNEL_POOL_SIZE are treated as MAX_TUNNEL_POOL_SIZE.",
                "Higher values increase bandwidth usage."
            ]
        },
        "StaggerConnectionWorkersMilliseconds": {
            "description": "Adds a delay (in milliseconds) before making each server candidate available to connection workers. This option is enabled when > 0.",
            "examples": [
                "100  # moderate spacing",
                "250  # standard delay",
                "500  # extended delay"
            ],
            "notes": []
        },
        "NetworkLatencyMultiplier": {
            "description": "A float multiplier applied to network event timeouts for slow network adaptation.",
            "examples": [
                "1.0   # normal timing",
                "1.5   # moderate tolerance",
                "3.0   # extreme tolerance"
            ],
            "notes": [
                "Must be ≥ 1.0"
            ]
        },
        "LimitRelayBufferSizes": {
            "description": "Selects smaller buffers for port forward relaying.",
            "examples": [
                "true   # enable buffer size reduction",
                "false  # use default buffer sizes"
            ],
            "notes": []
        },
        "EgressRegion": {
            "description": "Specifies a ISO 3166-1 alpha-2 country code which indicates which country to egress from. For the default, '', the best performing server in any country is selected.",
            "examples": [
                "US   # Exit via United States",
                "SG   # Exit via Singapore"
            ],
            "notes": ["Enter in capital letters."]
        },
        "DeviceRegion": {
            "description": "The optional, reported region the host device is running in. This input value should be a ISO 3166-1 alpha-2 country code.",
            "examples": [
                "US  # United States",
                "IR  # Iran",
                "JP  # Japan"
            ],
            "notes": [
                "The device region is reported to the server in the connected request and recorded for Psiphon stats.",
                "When provided, this value may be used, pre-connection, to select performance or circumvention optimization strategies for the given region."
            ]
        },
        "LimitTunnelProtocols": {
            "description": "Indicates which protocols to use. Valid values include: 'SSH', 'OSSH', 'TLS-OSSH', 'UNFRONTED-MEEK-OSSH', 'UNFRONTED-MEEK-HTTPS-OSSH', 'UNFRONTED-MEEK-SESSION-TICKET-OSSH', 'FRONTED-MEEK-OSSH', 'FRONTED-MEEK-HTTP-OSSH', 'QUIC-OSSH', 'FRONTED-MEEK-QUIC-OSSH', 'TAPDANCE-OSSH', 'CONJURE-OSSH', and 'SHADOWSOCKS-OSSH'.",
            "examples": [
                "[\"OSSH\"]           # only use OSSH protocol",
                "[\"QUIC-OSSH\", \"TLS-OSSH\"] # allow QUIC and TLS-based OSSH",
                "[]                   # allow all available protocols"
            ],
            "notes": [
                "For the default, an empty list, all protocols are used."
            ]
        },
        "EstablishTunnelPausePeriodSeconds": {
            "description": "Specifies the delay between attempts to establish tunnels. Briefly pausing allows for network conditions to improve and for asynchronous operations such as fetch remote server list to complete. If omitted, a default value is used.",
            "examples": [
                "1   # 1 second pause",
                "5   # 5 seconds between attempts",
                "10  # 10 seconds delay"
            ],
            "notes": [
                "This value is typically overridden for testing."
            ]
        },
        "SplitTunnelRegions": {
            "description": "Enables selected split tunnel mode in which the client specifies a list of ISO 3166-1 alpha-2 country codes for which traffic should be untunneled.",
            "examples": [
                "[\"IR\"]",
                "[\"CN\", \"HK\"]"
            ],
            "notes": [
                "TCP port forwards destined to any country specified in SplitTunnelRegions will be untunneled, regardless of whether SplitTunnelOwnRegion is on or off."
            ]
        },
        "RemoteServerListUrl": {
            "description": "URL for downloading the list of Psiphon servers (HTTPS required).",
            "examples": [
                "https://example.com/list",
                "https://psiphon.net/remote_list"
            ],
            "notes": [
                "Must be reachable over HTTPS.",
                "Used when remote server updates are required."
            ]
        }
    }

    entry = PARAMETER_HELPS.get(key)
    if entry:
        output = []

        output.append(f"{src_utils.BOLD}📘 Description:{src_utils.RESET}\n{entry['description']}\n")

        if entry.get("examples"):
            ex_list = "\n".join([f"  - {src_utils.GREEN}{ex}{src_utils.RESET}" for ex in entry["examples"]])
            output.append(f"{src_utils.BOLD}🔍 Examples:{src_utils.RESET}\n{ex_list}\n")

        if entry.get("notes"):
            nt_list = "\n".join([f"  • {note}" for note in entry["notes"]])
            output.append(f"{src_utils.BOLD}💡 Notes:{src_utils.RESET}\n{nt_list}")

        return "\n".join(output)

    # fallback legacy help
    old_help = help_texts.get(key)
    return old_help if old_help else "No help available for this parameter."




#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#



def generate_psiphon_config(
    EgressRegion="",
    socks_port=1081,
    http_port=8081,
    remote_server_list_url="https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
):
    """
    Generates a fresh Psiphon configuration file.

    Removes any existing config and writes a new JSON file with
    pre-defined defaults and selected region and ports.

    Assumes inputs are validated beforehand.

    Args:
        EgressRegion (str): Country/region code for exit node.
        socks_port (int): Local SOCKS proxy port.
        http_port (int): Local HTTP proxy port.
        remote_server_list_url (str): URL for Psiphon server list.

    Returns:
        bool: True if config written successfully, False otherwise.
    """
    src_utils.info(f"Generating Psiphon config for region: {EgressRegion}")

    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
    except PermissionError:
        src_utils.error(f"Permission denied: Can't create directory {CONFIG_DIR}", solution="Run as root")
        return False
    except Exception as e:
        src_utils.error(f"Failed to create config directory: {str(e)}")
        return False

    if src_utils.file_exists(CONFIG_FILE):
        try:
            os.remove(CONFIG_FILE)
            src_utils.info(f"Existing config file removed: {CONFIG_FILE}")
        except PermissionError:
            src_utils.error(f"Permission denied: Can't remove existing config {CONFIG_FILE}", solution="Run as root")
            return False
        except Exception as e:
            src_utils.error(f"Failed to remove existing config: {str(e)}")
            return False

    config = {

        "PropagationChannelId": "FFFFFFFFFFFFFFFF",
        "SponsorId": "FFFFFFFFFFFFFFFF",
        "RemoteServerListDownloadFilename": "remote_server_list",
        "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
        "RemoteServerListUrl": "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",

        "DataRootDirectory": "/opt/psiphon",
        
        "LocalHttpProxyPort": 8081,
        "LocalSocksProxyPort": 1081,
        "EgressRegion": f"{EgressRegion}",
        "DeviceRegion": "",


        "ConnectionWorkerPoolSize": 40,
        "TunnelPoolSize": 2,

        "StaggerConnectionWorkersMilliseconds": 150,
        "NetworkLatencyMultiplier": 1.0,

        "EmitDiagnosticNotices": True,
        
        "UseNoticeFiles": {
        "MaxSizeBytes": 51200,
        "MaxRotateCount": 1
        }

    }

    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4, separators=(',', ': '))
        src_utils.success("Config file generated successfully.", newline=False)
    except PermissionError:
        src_utils.error(f"Permission denied: Can't write to {CONFIG_FILE}", solution="Run as root")
        return False
    except Exception as e:
        src_utils.error(f"Failed to generate config: {str(e)}", solution="Check disk space or file system issues")
        return False


    return True




#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#





def get_system_architecture():
    """
    Detects the system architecture using os.uname().

    Returns:
        str: "x86_64" for 64-bit systems,
             "i386" for 32-bit (with user confirmation),
             or None if unsupported or error occurs.
    """
    try:
        arch = os.uname().machine
        src_utils.info(f"System architecture detected: {arch}")
        

        supported_archs = {
            "x86_64": "x86_64",
            "amd64": "x86_64",
            "x86-64": "x86_64",
            "x64": "x86_64"
        }
        
        if arch in supported_archs:
            return supported_archs[arch]
        

        if re.match(r'^(i\d86|x86)$', arch):
            src_utils.warning("32-bit architecture detected")
            if src_utils.get_confirmation(f"{src_utils.YELLOW}⚠️Continue anyway?(y/n) : {src_utils.RESET}"):
                return "i386"
            return None
        
        src_utils.error(f"Unsupported architecture: {arch}", solution="Only x86_64 is supported")
        return None
    
    except Exception as e:
        src_utils.error(f"Failed to detect system architecture: {str(e)}")
        return None




#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#




def create_systemd_service():
    """
    Creates and enables a systemd service unit for Psiphon.

    - Overwrites any existing psiphon.service.
    - Automatically reloads daemon, enables, and starts the service.

    Returns:
        bool: True if service was successfully created and started, False otherwise.
    """

    service_content = f"""
[Unit]
Description=Psiphon Tunnel Core
After=network.target
StartLimitIntervalSec=10
StartLimitBurst=50

[Service]
ExecStart={PSIPHON_BINARY} -config {CONFIG_FILE}
ExecStopPost=/bin/sleep 2
Restart=always
RestartSec=1
User=root

[Install]
WantedBy=multi-user.target
"""


    src_utils.info(f"Generating Psiphon Systemd service")
    if os.path.exists(SERVICE_PATH):
        if not remove_existing_service():
            src_utils.warning(
                "⚠️ Could not remove existing service file.",
                solution="Check permissions or stop the service manually."
            )

    try:
        with open(SERVICE_PATH, "w") as f:
            f.write(service_content)
        
        src_utils.run_command("systemctl daemon-reload")
        src_utils.run_command("systemctl enable psiphon")
        src_utils.run_command("systemctl start psiphon")
        
        src_utils.success("Systemd service created and started.", newline=False)
        return True
    
    except PermissionError:
        src_utils.error(f"Permission denied: Can't write to {SERVICE_PATH}", solution="Run as root")
        return False
    
    except Exception as e:
        src_utils.error(f"Failed to create systemd service: {str(e)}")
        return False







#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#







def check_parameters(target_keys=None, validate=False, validate_json=True, print_output=False):
    """
    Analyze and optionally validate Psiphon configuration parameters.

    This function loads the Psiphon JSON configuration file, checks for the presence 
    and values of specific keys, and optionally validates them against a defined schema (PARAMETER_RULES).
    It can also print the results in a formatted and colored style if required.

    Parameters:
    -----------
    target_keys : str, list, True, or None, optional
        - str  : check a single key by name.
        - list : check a list of keys.
        - True : check all keys present in the config file.
        - None : skip key validation, only validate overall JSON structure (used with validate_json=True).

    validate : bool, optional (default=False)
        Whether to validate the values of the given keys according to PARAMETER_RULES.

    validate_json : bool, optional (default=True)
        Whether to validate the entire JSON structure.
        If enabled and the JSON is invalid, returns:
        {
            "__config__": {
                "valid": False,
                "error": "Syntax error message here"
            }
        }

    print_output : bool, optional (default=False)
        Whether to print a formatted output of parameters and validation status.

    Returns:
    --------
    dict
        Behavior depends on the parameters:

        If validate_json=True and JSON is invalid:
            {
                "__config__": {
                    "valid": False,
                    "error": "..."
                }
            }

        If target_keys is None and JSON is valid:
            {
                "__config__": {
                    "valid": True
                }
            }

        If checking one or more parameters:
            {
                "ParamName": {
                    "value": <actual value or None>,
                    "valid": True | False | None
                },
                ...
            }

        - `valid = True`   → key is valid according to the schema.
        - `valid = False`  → key is present but invalid format/type/value.
        - `valid = None`   → key is not validated (because validate=False or key missing).
        - `value = None`   → key not found in the config.

    Examples:
    ---------
    # 1. Check if the Psiphon config file is valid JSON:
    result = check_parameters(validate_json=True)
    if result.get("__config__", {}).get("valid") == False:
        print("Config file is invalid JSON")

    # 2. Retrieve value of a single key without validating:
    result = check_parameters(target_keys="LocalSocksProxyPort")
    port = result.get("LocalSocksProxyPort", {}).get("value")

    # 3. Validate and print the status of multiple keys:
    check_parameters(
        target_keys=["LocalHttpProxyPort", "TunnelPoolSize"],
        validate=True,
        print_output=True
    )

    # 4. Check all available keys and validate all:
    result = check_parameters(target_keys=True, validate=True)

    # 5. Use in silent mode (only return data for internal use):
    result = check_parameters(
        target_keys="LimitTunnelProtocols",
        validate=True,
        print_output=False
    )
    if result["LimitTunnelProtocols"]["valid"] is False:
        print("⚠ LimitTunnelProtocols setting is invalid!")

    Notes:
    ------
    - The configuration file path is defined in CONFIG_FILE (usually: /etc/psiphon/config.json).
    - Schema rules are defined in PARAMETER_RULES for type, range, length, casing, etc.
    - This function is designed to be reusable by both CLI menus and programmatic backends (advanced settings, editors).
    """
    if not src_utils.file_exists(CONFIG_FILE):
        if print_output:
            src_utils.error("Psiphon config not found", solution="Install Psiphon first")
        return False

    try:
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)
    except json.JSONDecodeError as e:
        if validate_json:
            if print_output:
                src_utils.error("Invalid JSON in Psiphon config", solution=str(e))
            return {
                "__config__": {
                    "valid": False,
                    "error": str(e)
                }
            }
        else:
            return {"__config__": {"valid": True}}

    def is_valid(k, v):
        rule = PARAMETER_RULES.get(k)
        if not rule:
            return True
        if not isinstance(v, rule["type"]):
            return False
        if isinstance(v, str) and v == "" and rule.get("allow_empty"):
            return True
        if rule["type"] == int and "range" in rule:
            return rule["range"][0] <= v <= rule["range"][1]
        if rule["type"] == str:
            if "length" in rule and len(v) != rule["length"]:
                return False
            if "min_length" in rule and len(v) < rule["min_length"]:
                return False
            if "startswith" in rule and not v.startswith(rule["startswith"]):
                return False
            if rule.get("uppercase") and v.upper() != v:
                return False
        if rule["type"] == list:
            if not isinstance(v, list):
                return False
            if rule.get("uppercase_all"):
                if not all(isinstance(i, str) and i.upper() == i for i in v):
                    return False
            if "allowed_values" in rule:
                if not all(i in rule["allowed_values"] for i in v):
                    return False
        return True

    keys_to_check = []
    if isinstance(target_keys, str):
        keys_to_check = [target_keys]
    elif isinstance(target_keys, list):
        keys_to_check = target_keys
    elif target_keys is True:
        keys_to_check = list(config_data.keys())
    else:
        keys_to_check = []

    if not keys_to_check:
        return config_data

    result = {}

    if print_output:
        print("\n" + "="*40)
        print(f"{src_utils.HEADER_COLOR}{'Psiphon Configuration:'.center(38)}{src_utils.RESET}")
        print("="*40 + "\n")

    for k in keys_to_check:
        entry = {"value": None, "valid": None}
        if k not in config_data:
            if print_output:
                src_utils.warning(f"Key '{k}' not found in config")
            result[k] = entry
            continue
        v = config_data[k]
        entry["value"] = v
        if validate:
            entry["valid"] = is_valid(k, v)
        if print_output:
            val_str = f'"{v}"' if isinstance(v, str) else repr(v)
            src_utils.info(f"{k.ljust(2)} : {val_str}")
            if validate:
                if entry["valid"]:
                    src_utils.success(f"'{k}' is valid", newline=False)
                else:
                    src_utils.warning(f"'{k}' is INVALID", solution="Fix type or format", newline=False)
        result[k] = entry

    if print_output:
        print("\n" + "="*40)

    return result




#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#




def manage_parameters(key, value=None, disable=False, config_path=CONFIG_FILE, print_output=True):
    """
    Safely add, update, or disable one or multiple parameters in the Psiphon configuration JSON file.

    This function manages key-value pairs in the Psiphon config with validation, structured feedback,
    and optionally supports batch updates when 'key' is a dictionary.

    Parameters:
    ------------
    key : str or dict
        The configuration key to modify, or a dictionary of {key: value} pairs.
        If a dict is provided, the function loops through and processes each pair.

    value : any, optional (default: None)
        The value to assign to the key. Ignored if 'key' is a dictionary.

    disable : bool, optional (default: False)
        If True, the specified key or list of keys will be removed from the config.
        If 'key' is a dict, keys in it will be disabled if listed in 'disable_keys'.

    config_path : str, optional
        Path to the config JSON file. Default is CONFIG_FILE constant.

    print_output : bool, optional
        If True, feedback is printed to screen. If False, only returned as dict.

    Returns:
    --------
    dict
        If input is single key → dict with fields:
            - success (bool)
            - message (str)
            - valid (bool or None)
            - previous_value (any)
            - new_value (any)
            - disabled (bool)

        If input is dict of keys → dict of {key: result_dict}

    Examples:
    ---------
    >>> manage_parameters("EgressRegion", "US")
    >>> manage_parameters("TunnelPoolSize", disable=True)

    Batch mode:
    >>> manage_parameters({"EgressRegion": "US", "LocalHttpProxyPort": 8081})

    Programmatically:
    >>> res = manage_parameters("LocalSocksProxyPort", 1081, print_output=False)
    >>> if res["success"]: print("Updated!")
    """
    # ─────────────────────────────────────────────────────
    if not os.access(config_path, os.W_OK):
        src_utils.error(f"Permission denied: Can't write to {config_path}")
        return {"success": False, "message": "Write permission denied"}
    # MULTI-MODE: Batch dictionary input
    if isinstance(key, dict):
        batch_results = {}
        # ─ Step 0: Load config once
        if not src_utils.file_exists(config_path):
            msg = "Configuration file not found."
            if print_output:
                src_utils.error(msg)
            return {k: {"success": False, "message": msg} for k in key}
        try:
            with open(config_path, "r") as f:
                config_data = json.load(f)
        except json.JSONDecodeError as e:
            msg = f"Invalid JSON format: {str(e)}"
            if print_output:
                src_utils.error(msg)
            return {k: {"success": False, "message": msg} for k in key}
        
        # ─ Step 1: Validate all
        pending_updates = {}
        batch_results = {}

        for k, v in key.items():
            res = {
                "success": False,
                "message": "",
                "previous_value": config_data.get(k),
                "new_value": None,
                "valid": None,
                "disabled": False
            }

            rule = PARAMETER_RULES.get(k)
            if not rule:
                res["message"] = f"Key '{k}' is not defined in PARAMETER_RULES."
                if print_output:
                    src_utils.warning(res["message"])
                batch_results[k] = res
                continue

            def is_valid_value(val):
                if not isinstance(val, rule["type"]):
                    return False
                if isinstance(val, str):
                    if val == "" and rule.get("allow_empty"):
                        return True
                    if rule.get("length") and len(val) != rule["length"]:
                        return False
                    if rule.get("min_length") and len(val) < rule["min_length"]:
                        return False
                    if rule.get("startswith") and not val.startswith(rule["startswith"]):
                        return False
                    if rule.get("uppercase") and val.upper() != val:
                        return False
                elif isinstance(val, list):
                    if rule.get("uppercase_all") and not all(isinstance(i, str) and i.upper() == i for i in val):
                        return False
                    if rule.get("allowed_values") and not all(i in rule["allowed_values"] for i in val):
                        return False
                elif isinstance(val, int) and rule.get("range"):
                    min_val, max_val = rule["range"]
                    if not (min_val <= val <= max_val):
                        return False
                return True

            is_valid = is_valid_value(v)
            res["valid"] = is_valid
            if not is_valid:
                res["message"] = f"Provided value for '{k}' is invalid."
                if print_output:
                    src_utils.warning(res["message"])
                batch_results[k] = res
                continue

            if k in config_data and not is_valid_value(config_data[k]):
                del config_data[k]
            config_data[k] = v
            res.update({
                "success": True,
                "new_value": v,
                "message": f"Parameter '{k}' updated successfully."
            })
            if print_output:
                src_utils.success(res["message"])
            batch_results[k] = res

        # ─ Step 2: Save after all
        try:
            with open(config_path, "w") as f:
                json.dump(config_data, f, indent=4)
            if print_output:
                src_utils.success("Configuration file saved successfully.")
        except Exception as e:
            for r in batch_results.values():
                r["success"] = False
                r["message"] = f"Failed to write config: {str(e)}"
            if print_output:
                src_utils.error(f"Failed to write config: {str(e)}")
        return batch_results
    # ─────────────────────────────────────────────────────

    # ─ SINGLE PARAMETER MODE ─
    result = {
        "success": False,
        "message": "",
        "previous_value": None,
        "new_value": None,
        "valid": None,
        "disabled": False
    }

    # Step 1: Check config file existence
    if not src_utils.file_exists(config_path):
        result["message"] = "Configuration file not found."
        if print_output:
            src_utils.error(result["message"])
        return result

    # Step 2: Load and validate JSON
    try:
        with open(config_path, "r") as f:
            config_data = json.load(f)
    except json.JSONDecodeError as e:
        result["message"] = f"Invalid JSON format: {str(e)}"
        if print_output:
            src_utils.error(result["message"])
        return result

    # Step 3: If disable=True, remove the key
    if disable:
        result["previous_value"] = config_data.pop(key, None)
        result.update({
            "success": True,
            "disabled": True,
            "message": f"Parameter '{key}' has been disabled.",
            "valid": None
        })
        if print_output:
            src_utils.success(result["message"])
        # Save after removal
        try:
            with open(config_path, "w") as f:
                json.dump(config_data, f, indent=4)
            if print_output:
                src_utils.success("Configuration updated after disabling parameter.")
        except Exception as e:
            result["success"] = False
            result["message"] = f"Failed to write config: {str(e)}"
            if print_output:
                src_utils.error(result["message"])
        return result

    # Step 4: If value is None, do nothing
    if value is None:
        result["message"] = "No value provided and disable=False. Nothing to do."
        if print_output:
            src_utils.warning(result["message"])
        return result

    # Step 5: Validate key and value
    rule = PARAMETER_RULES.get(key)
    if not rule:
        result["message"] = f"Key '{key}' is not defined in PARAMETER_RULES."
        if print_output:
            src_utils.warning(result["message"], solution="Unsupported parameter.")
        return result

    def is_valid_value(val):
        if not isinstance(val, rule["type"]):
            return False
        if isinstance(val, str):
            if val == "" and rule.get("allow_empty"):
                return True
            if rule.get("length") and len(val) != rule["length"]:
                return False
            if rule.get("min_length") and len(val) < rule["min_length"]:
                return False
            if rule.get("startswith") and not val.startswith(rule["startswith"]):
                return False
            if rule.get("uppercase") and val.upper() != val:
                return False
        elif isinstance(val, list):
            if rule.get("uppercase_all") and not all(isinstance(i, str) and i.upper() == i for i in val):
                return False
            if rule.get("allowed_values") and not all(i in rule["allowed_values"] for i in val):
                return False
        elif isinstance(val, int) and rule.get("range"):
            min_val, max_val = rule["range"]
            if not (min_val <= val <= max_val):
                return False
        return True

    is_valid = is_valid_value(value)
    result["valid"] = is_valid

    if not is_valid:
        result["message"] = f"Provided value for '{key}' is invalid."
        if print_output:
            src_utils.warning(result["message"], solution="Review value format.")
        return result

    # Step 6: Replace value
    if key in config_data and not is_valid_value(config_data[key]):
        del config_data[key]  # Remove invalid existing value first

    result["previous_value"] = config_data.get(key)
    config_data[key] = value
    result.update({
        "success": True,
        "new_value": value,
        "message": f"Parameter '{key}' updated successfully."
    })
    if print_output:
        src_utils.success(result["message"])

    # Step 7: Save file
    try:
        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=4)
        if print_output:
            src_utils.success("Configuration file saved successfully.")
    except Exception as e:
        result["success"] = False
        result["message"] = f"Failed to write config: {str(e)}"
        if print_output:
            src_utils.error(result["message"])

    return result




#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#




def manual_config_psiphon(config_path=CONFIG_FILE):
    """
    Allows user to manually edit Psiphon config file (JSON) with safety and backup mechanisms.

    Steps:
    -------
    1. Ensure config exists
    2. Create unique backup with UUID
    3. Open nano editor for user
    4. After edit, validate JSON format
    5. If invalid:
        - Ask to restore from backup
        - Restore if accepted
    6. Remove backup in all cases
    7. Print outcome and exit

    Parameters:
    ------------
    config_path : str (default: CONFIG_FILE)
        Path to Psiphon configuration file

    Returns:
    --------
    bool
        True if everything went fine or user kept modified version, False if serious failure occurred
    """

    src_utils.clear_screen()
    print("===============================================")
    print("         Manual Psiphon Configuration")
    print("===============================================\n")

    # Step 1: Check if config exists
    if not src_utils.file_exists(config_path):
        src_utils.error("Psiphon config file not found.", solution="Install Psiphon first")
        return False

    print("\n===============================================")
    # Step 2: Create backup
    backup_uuid = str(uuid.uuid4())[:8]
    backup_path = f"{config_path}.backup_{backup_uuid}"
    try:
        shutil.copyfile(config_path, backup_path)
        src_utils.success("Backup created", details=f"Path: {backup_path}")
    except Exception as e:
        src_utils.error(f"Failed to create backup: {str(e)}", solution="Check permissions or disk space")
        return False

    # Step 3: Open editor
    src_utils.info("Opening nano editor to edit config file...")
    os.system(f"sudo nano {config_path}")

    # Step 4: Validate new JSON
    try:
        with open(config_path, "r") as f:
            json.load(f)
        src_utils.success("✅ Psiphon config is valid after edit.")
    except json.JSONDecodeError as e:
        src_utils.warning("⚠️ Invalid JSON detected after manual edit.", solution=str(e))

        # Step 5: Ask to restore backup
        restore_choice = src_utils.get_confirmation("Restore original configuration from backup? (Y/n): ")
        if restore_choice:
            try:
                shutil.copyfile(backup_path, config_path)
                src_utils.success("Restored configuration from backup", details=backup_path)
            except Exception as e:
                src_utils.error(f"Failed to restore backup: {str(e)}", solution="Manually copy backup file")
                return False
        else:
            src_utils.warning("Keeping invalid configuration. This may break Psiphon.")
    
    # Step 6: Cleanup
    try:
        os.remove(backup_path)
        src_utils.info("Backup removed", details=backup_path)
    except Exception as e:
        src_utils.warning(f"Failed to remove backup: {str(e)}", solution="Delete manually")
        

    # Step 7: Restart Psiphon Service
    try:
        restart_psiphon()
    except Exception as e:
        src_utils.warning(f"Failed to Restart: {str(e)}", solution="Restart manually")

    print("\n===============================================")

    src_utils.success("✅ Manual configuration complete.")
    return True



#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#



def remove_existing_service():
    src_utils.info("Checking for existing Psiphon service and related units...")

    unit_paths = [
        "/etc/systemd/system/psiphon.service"
    ]

    for path in unit_paths:
        if src_utils.file_exists(path):
            unit_name = os.path.basename(path)
            src_utils.info(f"Found unit {unit_name}. Cleaning up...")

            if not src_utils.run_command(f"systemctl stop {unit_name}",
                                        error_message=f"Failed to stop {unit_name}"):
                src_utils.warning(f"Could not stop {unit_name}")

            if not src_utils.run_command(f"systemctl disable {unit_name}",
                                        error_message=f"Failed to disable {unit_name}"):
                src_utils.warning(f"Could not disable {unit_name}")

            try:
                os.remove(path)
                src_utils.success(f"Removed unit file: {path}", newline=False)
            except PermissionError:
                src_utils.error(f"Permission denied: Can't remove {path}", solution="Run as root")
                return False
            except Exception as e:
                src_utils.error(f"Failed to remove {path}: {str(e)}")
                return False

    src_utils.success("✅ Previous service and related units handled successfully.")
    return True



#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#


def show_tuning_menu():
    """
    Presents a menu to apply predefined network optimization profiles to Psiphon configuration.

    Three performance profiles are available:
    1. Conservative: Minimal resource usage for restricted networks
    2. Balanced: Moderate performance for general use
    3. Aggressive: Maximum speed with higher resource consumption
    Returns:
    --------
    None
    """
    if not Path(CONFIG_FILE).is_file():
        src_utils.error("Config file not found.", solution="Generate it first.")
        input(f"{src_utils.CYAN}Press Enter to return...{src_utils.RESET}")
        return

    levels = {
        "1": {
            "title": "Level 1 - Conservative",
            "description": (f"""️{src_utils.CYAN}🛡️ Suitable for slow networks or Low End Systems.
- Worker Pool Size: Disabled (The default will be selected by Psiphon.).
- Stagger Workers: Disabled (The default will be selected by Psiphon.).
- Latency Multiplier: 2.0x (higher tolerance for unstable connections).
Suitable for: Mobile, unstable, or restricted networks.{src_utils.RESET}"""),
            "settings": {
                "NetworkLatencyMultiplier": 2.0,
                "StaggerConnectionWorkersMilliseconds": {"disable": True},
                "ConnectionWorkerPoolSize": {"disable": True},
                "TunnelPoolSize": {"disable": True},
                "LimitRelayBufferSizes": {"disable": True}
            }
        },
        "2": {
            "title": "Level 2 - Balanced",
            "description": (f"""️{src_utils.CYAN}⚖️ Balanced performance and reliability.
- Worker Pool Size: 40 (moderate resource usage).
- Stagger Workers: 150ms 
- Latency Multiplier: 1.0 (for normal internet speeds).
- Tunnel Pool Size: 2 (Increased connection stability).
Suitable for: General use in normal environments to increase connection speed and maintain a longer connection.{src_utils.RESET}"""),
            "settings": {
                "ConnectionWorkerPoolSize": 40,
                "StaggerConnectionWorkersMilliseconds": 150,
                "NetworkLatencyMultiplier": 1.0,
                "TunnelPoolSize": 2,
                "LimitRelayBufferSizes": {"disable": True}
            }
        },
        "3": {
            "title": "Level 3 - Aggressive",
            "description": (f"""️{src_utils.CYAN}🚀 Optimized for increase connection speed.
- Worker Pool Size: 60 (higher parallelism)
- Stagger Workers: 150ms 
- Latency Multiplier: 1.0
- Buffer Limits: Disabled
- Tunnel Pool Size: 4 (Increased connection stability).
Suitable for: Less connection latency - More connection stability.{src_utils.RESET}"""),
            "settings": {
                "ConnectionWorkerPoolSize": 60,
                "StaggerConnectionWorkersMilliseconds": 150,
                "NetworkLatencyMultiplier": 1.0,
                "TunnelPoolSize": 4,
                "LimitRelayBufferSizes": False
            }
        }
    }

    print(f"\n{src_utils.BOLD}{src_utils.GREEN}=== Tuning Menu ==={src_utils.RESET}\n")
    for key, level in levels.items():
        print(f"{src_utils.CYAN}{key} |{src_utils.RESET} {level['title']}")

    choice = input(f"{src_utils.YELLOW}\nSelect tuning level (1/2/3 or 'q' to quit): {src_utils.RESET}").strip()

    if choice not in levels:
        src_utils.warning("Cancelled or invalid choice.")
        return

    level = levels[choice]
    print(f"\n{src_utils.GREEN}🔧 {level['title']}{src_utils.RESET}")
    print(level['description'])

    confirm = input(f"\n{src_utils.YELLOW}Apply these settings? (y = yes, n = back): {src_utils.RESET}").lower().strip()

    if confirm != "y":
        src_utils.info("Back to main menu.")
        return

    print(f"\n{src_utils.CYAN}Applying tuning profile settings...{src_utils.RESET}")

    batch_values = {}
    for param_key, param in level["settings"].items():
        if isinstance(param, dict) and param.get("disable"):
            continue
        if isinstance(param, dict):
            batch_values[param_key] = param["value"]
        else:
            batch_values[param_key] = param

    if batch_values:
        manage_parameters(batch_values, print_output=True)

    for param_key, param in level["settings"].items():
        if isinstance(param, dict) and param.get("disable"):
            manage_parameters(param_key, disable=True, print_output=True)

    src_utils.success("Done.")
    input(f"{src_utils.CYAN}Press Enter to return...{src_utils.RESET}")




#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#



def reset_config():
    """
    Resets the Psiphon configuration to default by creating/overwriting the config file.

    Example:
    >>> reset_config()
    🔁 Reset Configuration to Default
    ✅ Configuration successfully written to /etc/psiphon/psiphon.conf
    """
    print("\n🔁 Reset Configuration to Default")

    if not os.path.exists(PSIPHON_BINARY) or not os.path.exists("/etc/systemd/system/psiphon.service"):
        print("❌ Psiphon does not appear to be installed correctly.")
        print("   Missing files:")
        if not os.path.exists(PSIPHON_BINARY):
            print(f"   - Binary not found: {PSIPHON_BINARY}")
        if not os.path.exists("/etc/systemd/system/psiphon.service"):
            print("   - Service file not found: /etc/systemd/system/psiphon.service")
        return

    if os.path.exists(CONFIG_FILE):
        confirm = input(f"\n⚠️ File already exists at {CONFIG_FILE}.\nAre you sure you want to overwrite it? (yes/no): ").strip().lower()
        if confirm not in ["yes", "y"]:
            print("❌ Operation cancelled.")
            return
    else:
        print("ℹ️ No existing configuration found. Creating a new one.")

    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=4)
        print(f"✅ Configuration successfully written to {CONFIG_FILE}")
    except Exception as e:
        print(f"❌ Failed to write config: {e}")


#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#


def stop_psiphon():
    """
    Stops the Psiphon service and cleans up related processes.

    Returns:
    --------
    None

    Example:
    --------
    >>> stop_psiphon()
    🔐 Stopping Psiphon service...
    ✅ Psiphon stopped successfully. All related processes terminated.
    """
    if not os.path.exists("/etc/systemd/system/psiphon.service"):
        print(f"ℹ️{src_utils.YELLOW} No existing service found.{src_utils.RESET}")
        return
    
    src_utils.info("Stopping Psiphon service...")

    src_utils.run_command("sudo systemctl stop psiphon", "Failed to stop psiphon service.")

    src_utils.run_command("systemctl daemon-reload", "Failed to re-execute systemd daemon.")

    src_utils.success("Psiphon stopped successfully", details="All related services and processes terminated", newline=False)



#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#



def restart_psiphon():
    """
    Restarts the Psiphon service with validation steps.

    Returns:
    --------
    bool
        True if restart command executed, but does NOT guarantee service is active

    Example:
    --------
    >>> restart_psiphon()
    🔐 Restarting Psiphon service...
    ✅ Psiphon restarted successfully and is active
    """
    if not os.path.exists("/etc/systemd/system/psiphon.service"):
        print(f"ℹ️{src_utils.YELLOW} No existing service found.{src_utils.RESET}")
        return
    
    src_utils.info("Restarting Psiphon service...")

    stop_psiphon()

    src_utils.run_command("sudo systemctl start psiphon", "Failed to start psiphon service")

    if not src_utils.run_command("sudo systemctl is-active psiphon", "Psiphon service is not active after restart"):
        src_utils.warning("Psiphon may not be active", solution="Check service manually with 'systemctl status psiphon'")
    else:
        src_utils.success("Psiphon restarted successfully and is active")

    return True



#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#






#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#



def is_psiphon_installed():
    """
    Checks if Psiphon is installed on the system by verifying key files/directories.

    Returns:
    --------
    bool
        True if any of the Psiphon service file or core directories exist, False otherwise

    Example:
    --------
    >>> if is_psiphon_installed():
    ...     print("Psiphon is installed")
    ... else:
    ...     print("Psiphon not found")
    """

    if (
        src_utils.file_exists("/etc/systemd/system/psiphon.service") or
        src_utils.file_exists("/opt/psiphon") or
        src_utils.file_exists("/etc/psiphon")
    ):
        return True

    return False



#=======================================================================
#======================parameters_visual_managerS=======================
#=======================================================================


def parameters_visual_manager_Navigator(mode, **kwargs):
    """
    Route to the appropriate visual parameter manager based on type.
    Supports passing extra arguments like allow_multiple.
    """
    handlers = {
        "int": parameters_visual_manager_int,
        "float": parameters_visual_manager_float,
        "bool": parameters_visual_manager_bool,
        "selector": parameters_visual_manager_selector_list,
        "text": parameters_visual_manager_text,
    }

    if mode not in handlers:
        raise ValueError(f"Unsupported mode: {mode}")
    
    return handlers[mode](**kwargs)




#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#




def parameters_visual_manager_int(key):
    """
    Provides a menu-driven interface to edit or disable a numeric configuration parameter.

    Parameters:
    -----------
    key : str
        The configuration parameter key to manage (must be a numeric type in PARAMETER_RULES)
    Example:
    --------
    >>> parameters_visual_manager_int("NetworkLatencyMultiplier")
    """


    src_utils.clear_screen()

    rule = PARAMETER_RULES.get(key)
    if not rule:
        src_utils.error(f"Parameter '{key}' not found in rules")
        input("Press Enter To Return")
        return

    print("=" * 40)
    print(f"{src_utils.YELLOW}{f'Edit parameter: '.center(40)}{src_utils.RESET}")
    print(f"{src_utils.HEADER_COLOR}{f'{key} '.center(40)}{src_utils.RESET}")
    print("=" * 40)
    print("\n")
    
    checked = check_parameters(target_keys=key, validate=True, print_output=False)

    if isinstance(checked, dict):
        config_meta = checked.get("__config__", {})
        if config_meta.get("valid") is False:
            src_utils.error("Invalid JSON in config file", details=config_meta.get("error", "Unknown error"))
            print("\nPlease fix the config file or reset it.")
            input("\nPress Enter to return")
            return
    else:
        src_utils.error("Failed to read configuration.", details="Check that Psiphon is installed.")
        input("\nPress Enter to return")
        return

    current = checked.get(key)

    if isinstance(current, dict) and "value" in current:
        value = current.get("value")
        valid = current.get("valid")
    else:
        value = current
        valid = None

    print(f"{src_utils.YELLOW}Current value: {value if value is not None else 'Not set'}{src_utils.RESET}")
    if value is None:
        print(f"{src_utils.RED}No value has been set yet for this parameter.{src_utils.RESET}")
    elif valid is False:
        print(f"{src_utils.RED}⚠️ Warning: The current value may be invalid.{src_utils.RESET}")
    else:
        print(f"{src_utils.GREEN}✔️ The current value looks valid.{src_utils.RESET}")

    print(f"\n{src_utils.YELLOW}Help: {src_utils.GREEN}{get_parameter_help(key)}{src_utils.RESET}")

    print(f"\n{src_utils.YELLOW}Example Correct value: {src_utils.GREEN}int (Number, such as 1 or 20, etc){src_utils.RESET}\n")

    while True:
        print(f"\n{src_utils.YELLOW}Options:{src_utils.RESET}")
        print("1 | Set new value")
        print("2 | Disable this parameter")
        print("0 | Cancel (no change)")

        choice = input(f"{src_utils.YELLOW}Enter your choice [0-2]: {src_utils.RESET}\n").strip()

        if choice == "1":
            new_value = input(f"\n{src_utils.YELLOW}Enter a new value for {src_utils.GREEN}{key}{src_utils.RESET} : ").strip()
            try:
                rule = PARAMETER_RULES.get(key)
                if rule["type"] == int:
                    parsed_value = int(new_value)
                elif rule["type"] == float:
                    parsed_value = float(new_value)
                elif rule["type"] == bool:
                    if new_value.lower() in ("true", "yes", "1"):
                        parsed_value = True
                    elif new_value.lower() in ("false", "no", "0"):
                        parsed_value = False
                    else:
                        raise ValueError("Invalid input for boolean")
                else:
                    parsed_value = new_value
            except Exception as e:
                src_utils.warning(f"Invalid input format: {e}")
                continue

            result = manage_parameters(key, value=parsed_value, print_output=True)
            input("\nPress Enter to return...")
            break

        elif choice == "2":
            result = manage_parameters(key, disable=True, print_output=True)
            input("\nPress Enter to return...")
            break

        elif choice == "0":
            break

        else:
            src_utils.warning("Invalid choice. Please enter a valid option.")





#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#




def parameters_visual_manager_float(key):
    """
    Menu-driven interface to edit or disable a float-type configuration parameter.

    Handles input validation and status display for numeric parameters requiring
    decimal values. Integrates with PARAMETER_RULES for range/validity checks.

    Args:
        key (str): Configuration parameter key (must be a float type in rules)

    Example:
    --------
    >>> parameters_visual_manager_float("NetworkLatencyMultiplier")
    """

    src_utils.clear_screen()

    rule = PARAMETER_RULES.get(key)
    if not rule:
        src_utils.error(f"Parameter '{key}' not found in rules")
        input("Press Enter To Return")
        return

    print("=" * 40)
    print(f"{src_utils.YELLOW}{f'Edit parameter: '.center(40)}{src_utils.RESET}")
    print(f"{src_utils.HEADER_COLOR}{f'{key} '.center(40)}{src_utils.RESET}")
    print("=" * 40)
    print("\n")
    
    checked = check_parameters(target_keys=key, validate=True, print_output=False)
    
    if isinstance(checked, dict):
        config_meta = checked.get("__config__", {})
        if config_meta.get("valid") is False:
            src_utils.error("Invalid JSON in config file", details=config_meta.get("error", "Unknown error"))
            print("\nPlease fix the config file or reset it.")
            input("\nPress Enter to return")
            return
    else:
        src_utils.error("Failed to read configuration.", details="Check that Psiphon is installed.")
        input("\nPress Enter to return")
        return

    current = checked.get(key)

    if isinstance(current, dict) and "value" in current:
        value = current.get("value")
        valid = current.get("valid")
    else:
        value = current
        valid = None

    print(f"{src_utils.YELLOW}Current value: {value if value is not None else 'Not set'}{src_utils.RESET}")
    if value is None:
        print(f"{src_utils.RED}No value has been set yet for this parameter.{src_utils.RESET}")
    elif valid is False:
        print(f"{src_utils.RED}⚠️ Warning: The current value may be invalid.{src_utils.RESET}")
    else:
        print(f"{src_utils.GREEN}✔️ The current value looks valid.{src_utils.RESET}")

    print(f"\n{src_utils.YELLOW}Help: {src_utils.GREEN}{get_parameter_help(key)}{src_utils.RESET}")

    print(f"\n{src_utils.YELLOW}Example Correct value: {src_utils.GREEN}float (Decimal number, such as 1 or 1.5, etc){src_utils.RESET}\n")

    while True:
        print(f"\n{src_utils.YELLOW}Options:{src_utils.RESET}")
        print("1 | Set new value")
        print("2 | Disable this parameter")
        print("0 | Cancel (no change)")

        choice = input(f"{src_utils.YELLOW}Enter your choice [0-2]: {src_utils.RESET}\n").strip()

        if choice == "1":
            new_value = input(f"\n{src_utils.YELLOW}Enter a new value for {src_utils.GREEN}{key}{src_utils.RESET} : ").strip()
            try:
                rule = PARAMETER_RULES.get(key)
                if rule["type"] == int:
                    parsed_value = int(new_value)
                elif rule["type"] == float:
                    parsed_value = float(new_value)
                elif rule["type"] == bool:
                    if new_value.lower() in ("true", "yes", "1"):
                        parsed_value = True
                    elif new_value.lower() in ("false", "no", "0"):
                        parsed_value = False
                    else:
                        raise ValueError("Invalid input for boolean")
                else:
                    parsed_value = new_value
            except Exception as e:
                src_utils.warning(f"Invalid input format: {e}")
                continue

            result = manage_parameters(key, value=parsed_value, print_output=True)
            input("\nPress Enter to return...")
            break

        elif choice == "2":
            result = manage_parameters(key, disable=True, print_output=True)
            input("\nPress Enter to return...")
            break


        elif choice == "0":
            break


        else:
            src_utils.warning("Invalid choice. Please enter a valid option.")





#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#





def parameters_visual_manager_bool(key):
    """
    Menu-driven interface to configure boolean parameters with validation.

    Allows enabling, disabling, or removing boolean settings. Displays current
    status, validation warnings, and parameter-specific help.

    Args:
        key (str): Configuration parameter key (must be a boolean type in rules)

    Returns:
    --------
    bool
        True if changes applied successfully, False on cancellation or error

    Example:
    --------
    >>> parameters_visual_manager_bool("SplitTunnelOwnRegion")
    """
    src_utils.clear_screen()

    rule = PARAMETER_RULES.get(key)
    if not rule:
        src_utils.error(f"Parameter '{key}' not found in rules")
        input("Press Enter To Return")
        return

    print("=" * 40)
    print(f"{src_utils.YELLOW}{'Edit parameter:'.center(40)}{src_utils.RESET}")
    print(f"{src_utils.HEADER_COLOR}{key.center(40)}{src_utils.RESET}")
    print("=" * 40, "\n")

    checked = check_parameters(target_keys=key, validate=True, print_output=False)
    
    if isinstance(checked, dict):
        config_meta = checked.get("__config__", {})
        if config_meta.get("valid") is False:
            src_utils.error("Invalid JSON in config file", details=config_meta.get("error", "Unknown error"))
            print("\nPlease fix the config file or reset it.")
            input("\nPress Enter to return")
            return
    else:
        src_utils.error("Failed to read configuration.", details="Check that Psiphon is installed.")
        input("\nPress Enter to return")
        return

    current = checked.get(key)

    if isinstance(current, dict) and "value" in current:
        value = current.get("value")
        valid = current.get("valid")
    else:
        value = current
        valid = None

    print(f"{src_utils.YELLOW}Current setting: {value}{src_utils.RESET}")
    if valid is False:
        print(f"{src_utils.RED}⚠️ Warning: Value may be invalid.{src_utils.RESET}")
    elif value is True:
        print(f"{src_utils.GREEN}✔️ Currently enabled.{src_utils.RESET}")
    elif value is False:
        print(f"{src_utils.GREEN}✔️ Currently disabled (false).{src_utils.RESET}")
    else:
        print(f"{src_utils.RED}Not set. Psiphon will use its default behavior.{src_utils.RESET}")

    print(f"\n{src_utils.YELLOW}Help: {src_utils.GREEN}{get_parameter_help(key)}{src_utils.RESET}\n")

    while True:
        print(f"{src_utils.YELLOW}Options:{src_utils.RESET}")
        print("1 | Enable (set true)")
        print("2 | Disable (set false)")
        print("3 | Remove parameter (Psiphon will auto-decide)")
        print("0 | Cancel (no change)")

        choice = input(f"{src_utils.YELLOW}Enter your choice [0-3]: {src_utils.RESET}\n").strip()
        if choice == "1":
            manage_parameters(key, value=True, print_output=True)
            break
        elif choice == "2":
            manage_parameters(key, value=False, print_output=True)
            break
        elif choice == "3":
            manage_parameters(key, disable=True, print_output=True)
            break
        elif choice == "0":
            break
        else:
            src_utils.warning("Invalid choice. Please enter 0-3.")
            


#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#




def parameters_visual_manager_selector_list(key, options_dict, allow_multiple=False):
    """
    Menu-driven interface to select and set parameters from a predefined list.

    Args:
        key (str): Configuration parameter key (must be a list/string type in rules)
        options_dict (dict): Valid options in {key: value} format (e.g., regions or protocols)
        allow_multiple (bool): Allow selecting multiple values (default: False)

    Returns:
        None
        
    parameters_visual_manager_selector_list(
    key="SplitTunnelRegions",
    options_dict=REGIONS,
    allow_multiple=True
    ) ....
    """
    src_utils.clear_screen()

    rule = PARAMETER_RULES.get(key)
    if not rule:
        src_utils.error(f"Parameter '{key}' not found in rules")
        input("Press Enter To Return")
        return

    print("=" * 44)
    print(f"{src_utils.YELLOW}{'Edit parameter:'.center(44)}{src_utils.RESET}")
    print(f"{src_utils.HEADER_COLOR}{key.center(44)}{src_utils.RESET}")
    print("=" * 44)

    checked = check_parameters(target_keys=key, validate=True, print_output=False)

    if isinstance(checked, dict):
        config_meta = checked.get("__config__", {})
        if config_meta.get("valid") is False:
            src_utils.error("Invalid JSON in config file", details=config_meta.get("error", "Unknown error"))
            print("\nPlease fix the config file or reset it.")
            input("\nPress Enter to return")
            return
    else:
        src_utils.error("Failed to read configuration.", details="Check that Psiphon is installed.")
        input("\nPress Enter to return")
        return

    current = checked.get(key)
    if isinstance(current, dict) and "value" in current:
        value = current.get("value")
        valid = current.get("valid")
    else:
        value = current
        valid = None

    print(f"{src_utils.YELLOW}Current value: {value if value else 'Not set'}{src_utils.RESET}")
    if valid is None:
        print(f"{src_utils.YELLOW}Unknown validation status.{src_utils.RESET}")
    elif valid is False:
        print(f"{src_utils.RED}⚠️ Warning: The current value may be invalid.{src_utils.RESET}")
    else:
        print(f"{src_utils.GREEN}✔️ The current value looks valid.{src_utils.RESET}")

    print(f"\n{src_utils.YELLOW}Help: {src_utils.GREEN}{get_parameter_help(key)}{src_utils.RESET}")

    sample_value = next(iter(options_dict.values()))
    if sample_value.startswith("SSH") or "OSSH" in sample_value:
        label = "protocol"
    elif len(sample_value) == 2 and sample_value.isalpha():
        label = "region"
    else:
        label = "item"

    options_for_display = dict(options_dict)

    if key == "EgressRegion":
        auto_key = str(max(map(int, options_for_display.keys())) + 1 if options_for_display else 1)
        options_for_display[auto_key] = "Auto"

    def print_grid(options, columns=4, label="item"):
        keys = list(options.keys())
        if label == "protocol":
            for k in keys:
                print(f"{k.rjust(2)}. {options[k]}")
        else:
            max_width = max(len(v) for v in options.values()) + 5
            for i in range(0, len(keys), columns):
                row = keys[i:i+columns]
                line = ""
                for k in row:
                    line += f"{k.rjust(2)}. {options[k].ljust(max_width)}"
                print(line)

    print(f"\n{src_utils.YELLOW}Available {label.title()}s:{src_utils.RESET}")
    print_grid(options_for_display, label=label)

    while True:
        print(f"\n{src_utils.YELLOW}Options:{src_utils.RESET}")
        print("1 | Set value(s)")
        print("2 | Disable parameter (remove from config)")
        print("0 | Cancel")

        choice = input(f"{src_utils.YELLOW}Enter your choice [0-2]: {src_utils.RESET}\n").strip()

        if choice == "1":
            if allow_multiple:
                prompt = f"Enter {label} number(s) separated by comma (e.g., 1,4,7): "
            else:
                if key == "EgressRegion":
                    prompt = f"Enter {label} number (e.g., 3) or press Enter for Auto: "
                else:
                    prompt = f"Enter {label} number (e.g., 3): "

            selected = input(f"\n{src_utils.YELLOW}{prompt}{src_utils.RESET}").strip()

            if key == "EgressRegion" and selected == "":
                value_to_set = ""
            else:
                selected_keys = [s.strip() for s in selected.split(",") if s.strip() in options_for_display]
                if not selected_keys:
                    src_utils.warning("Invalid selection. Please choose from listed numbers.")
                    continue

                selected_values = [options_for_display[k] for k in selected_keys]
                if "Auto" in selected_values:
                    value_to_set = ""
                else:
                    value_to_set = selected_values if allow_multiple else selected_values[0]

            manage_parameters(key, value=value_to_set, print_output=True)
            input("\nPress Enter to return...")
            break

        elif choice == "2":
            manage_parameters(key, disable=True, print_output=True)
            input("\nPress Enter to return...")
            break

        elif choice == "0":
            break
        else:
            src_utils.warning("Invalid choice. Please enter 0, 1 or 2.")



#===================================================================#
#-------------------------------------------------------------------#
#===================================================================#


def parameters_visual_manager_text(key):
    """
    Menu-driven interface to edit text/string configuration parameters with input validation.

    Args:
        key (str): Configuration parameter key (must be a string type in PARAMETER_RULES)

    Example:
    --------
    # Editing a URL parameter:
    >>> parameters_visual_manager_text("RemoteServerListUrl")
    """

    src_utils.clear_screen()

    rule = PARAMETER_RULES.get(key)
    if not rule:
        src_utils.error(f"Parameter '{key}' not found in rules")
        input("Press Enter To Return")
        return

    print("=" * 44)
    print(f"{src_utils.YELLOW}{'Edit parameter:'.center(44)}{src_utils.RESET}")
    print(f"{src_utils.HEADER_COLOR}{key.center(44)}{src_utils.RESET}")
    print("=" * 44)

    checked = check_parameters(target_keys=key, validate=True, print_output=False)
    
    if isinstance(checked, dict):
        config_meta = checked.get("__config__", {})
        if config_meta.get("valid") is False:
            src_utils.error("Invalid JSON in config file", details=config_meta.get("error", "Unknown error"))
            print("\nPlease fix the config file or reset it.")
            input("\nPress Enter to return")
            return
    else:
        src_utils.error("Failed to read configuration.", details="Check that Psiphon is installed.")
        input("\nPress Enter to return")
        return

    current = checked.get(key)

    if isinstance(current, dict) and "value" in current:
        value = current.get("value")
        valid = current.get("valid")
    else:
        value = current
        valid = None

    print(f"{src_utils.YELLOW}Current value: {value if value else 'Not set'}{src_utils.RESET}")
    if valid is None:
        print(f"{src_utils.YELLOW}Unknown validation status.{src_utils.RESET}")
    elif valid is False:
        print(f"{src_utils.RED}⚠️ Warning: The current value may be invalid.{src_utils.RESET}")
    else:
        print(f"{src_utils.GREEN}✔️ The current value looks valid.{src_utils.RESET}")

    print(f"\n{src_utils.YELLOW}Help: {src_utils.GREEN}{get_parameter_help(key)}{src_utils.RESET}")
    print(f"\n{src_utils.YELLOW}Example correct value: {src_utils.GREEN}string (e.g., https://example.com or any text){src_utils.RESET}\n")

    while True:
        print(f"{src_utils.YELLOW}Options:{src_utils.RESET}")
        print("1 | Set new value")
        print("2 | Disable parameter (remove from config)")
        print("0 | Cancel")

        choice = input(f"{src_utils.YELLOW}Enter your choice [0-2]: {src_utils.RESET}\n").strip()

        if choice == "1":
            new_value = input(f"\nEnter new value for {key}: ").strip()
            if not new_value:
                src_utils.warning("Empty input is not allowed.")
                continue
            result = manage_parameters(key, value=new_value, print_output=True)
            input("\nPress Enter to return...")
            break

        elif choice == "2":
            result = manage_parameters(key, disable=True, print_output=True)
            input("\nPress Enter to return...")
            break

        elif choice == "0":
            break

        else:
            src_utils.warning("Invalid choice. Please enter 0–2.")






#=======================================================================
#================================MENUS=================================
#=======================================================================




def display_advanced_psiphon_menu():
    while True:
        src_utils.clear_screen()
        print(f"{src_utils.BORDER_COLOR}╔{'═'*41}╗{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' ADVANCED PSIPHON SETTINGS '.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╠{'═'*41}╣{src_utils.RESET}")


        menu_items = [
            "1 | Connection & Performance Settings",
            "2 | Network Routing & Region Settings",
            "3 | Identity & Configuration Settings",
            "4 | Auto Optimization",
            "5 | Reset to default configuration",
            "6 | Restart to Save Changes"
        ]

        for item in menu_items:
            print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(39)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")

        print(f"{src_utils.BORDER_COLOR}╠{'═'*41}╣{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║ 0 | {src_utils.EXIT_STYLE}{'Back'.ljust(35)}{src_utils.RESET}{src_utils.BORDER_COLOR} ║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╚{'═'*41}╝{src_utils.RESET}")

        choice = input("\nEnter your choice: ").strip()
        if choice == "0":
            break
        elif choice == "1":
            psiphon_advanced_connections_menu()
        elif choice == "2":
            psiphon_advanced_region_menu()
        elif choice == "3":
            psiphon_advanced_Identity_menu()
        elif choice == "4":
            show_tuning_menu()
        elif choice == "5":
            reset_config()
            input("\nPress Enter to return...")
        elif choice == '6':  # Restart Psiphon
            src_utils.clear_screen()
            print("===============================================")
            print("              Restarting Psiphon")
            print("===============================================")
            restart_psiphon()
            input("\nPress Enter to return to Psiphon menu...")

        else:
            src_utils.warning("Invalid option selected", solution="Please choose from the list")
            input("Press Enter to continue...")
            display_advanced_psiphon_menu()




def psiphon_advanced_connections_menu():
    while True:
        src_utils.clear_screen()
        print(f"{src_utils.BORDER_COLOR}╔{'═'*45}╗{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' CONNECTION & PERFORMANCE SETTINGS '.center(45)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╠{'═'*45}╣{src_utils.RESET}")

        menu_items = [
            "1  | ⚙️ Set HTTP Proxy Port",
            "2  | ⚙️ Set SOCKS Proxy Port",
            "3  | ⚙️ Set Worker Pool Size",
            "4  | ⚙️ Set Tunnel Pool Size",
            "5  | ⚙️ Set Stagger Connection Workers",
            "6  | ⚙️ Set Tunnel Pause Period",
            "7  | ⚙️ Set Network Latency Multiplier",
            "8  | ⚙️ Set Relay Buffer Sizes Limit",
            "9  | ⚙️ Set Tunnel Protocols"
        ]

        for item in menu_items:
            print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(44)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")

        print(f"{src_utils.BORDER_COLOR}╠{'═'*45}╣{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║ 0 | {src_utils.EXIT_STYLE}{'Back to Advanced Menu'.ljust(39)}{src_utils.RESET}{src_utils.BORDER_COLOR} ║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╚{'═'*45}╝{src_utils.RESET}")

        choice = input("\nEnter your choice: ").strip()

        if choice == "0":
            break

        elif choice == "1":
            parameters_visual_manager_Navigator(mode="int", key="LocalHttpProxyPort")
        elif choice == "2":
            parameters_visual_manager_Navigator(mode="int", key="LocalSocksProxyPort")
        elif choice == "3":
            parameters_visual_manager_Navigator(mode="int", key="ConnectionWorkerPoolSize")
        elif choice == "4":
            parameters_visual_manager_Navigator(mode="int", key="TunnelPoolSize")
        elif choice == "5":
            parameters_visual_manager_Navigator(mode="int", key="StaggerConnectionWorkersMilliseconds")
        elif choice == "6":
            parameters_visual_manager_Navigator(mode="int", key="EstablishTunnelPausePeriodSeconds")
        elif choice == "7":
            parameters_visual_manager_Navigator(mode="float", key="NetworkLatencyMultiplier")

        elif choice == "8":
            parameters_visual_manager_Navigator(mode="bool", key="LimitRelayBufferSizes")
        elif choice == "9":
            parameters_visual_manager_Navigator(
                mode="selector",
                key="LimitTunnelProtocols",
                options_dict=tunnelprotocols,
                allow_multiple=True
            )

        else:
            src_utils.warning("Invalid option selected", solution="Please choose from the list")
            input("Press Enter to continue...")




def psiphon_advanced_region_menu():
    while True:
        src_utils.clear_screen()
        print(f"{src_utils.BORDER_COLOR}╔{'═'*44}╗{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' NETWORK ROUTING & REGION SETTINGS '.center(44)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╠{'═'*44}╣{src_utils.RESET}")

        menu_items = [
            "1 | ⚙️ Set Server Region",
            "2 | ⚙️ Set Own Region for Split Tunnel",
            "3 | ⚙️ Set Allowed Regions for Split Tunnel",
            "4 | ⚙️ Set Upstream Proxy URL"
        ]

        for item in menu_items:
            print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(43)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")

        print(f"{src_utils.BORDER_COLOR}╠{'═'*44}╣{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║ 0 | {src_utils.EXIT_STYLE}{'Back to Advanced Menu'.ljust(38)}{src_utils.RESET}{src_utils.BORDER_COLOR} ║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╚{'═'*44}╝{src_utils.RESET}")

        choice = input("\nEnter your choice: ").strip()

        if choice == "0":
            break

        elif choice == "1":
            parameters_visual_manager_Navigator(
                mode="selector",
                key="EgressRegion",
                options_dict=REGIONS,
                allow_multiple=False
            )
        elif choice == "2":
            parameters_visual_manager_Navigator(mode="bool", key="SplitTunnelOwnRegion")
        elif choice == "3":
            parameters_visual_manager_Navigator(
                mode="selector",
                key="SplitTunnelRegions",
                options_dict=REGIONS,
                allow_multiple=True
            )
        elif choice == "4":
            parameters_visual_manager_Navigator(mode="text", key="UpstreamProxyURL")


        else:
            src_utils.warning("Invalid option selected", solution="Please choose from the list")
            input("Press Enter to continue...")



def psiphon_advanced_Identity_menu():
    while True:
        src_utils.clear_screen()
        print(f"{src_utils.BORDER_COLOR}╔{'═'*41}╗{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' IDENTITY & CONFIGURATION SETTINGS '.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╠{'═'*41}╣{src_utils.RESET}")

        menu_items = [
            "1 | ⚙️ Set Propagation Channel ID",
            "2 | ⚙️ Set Sponsor ID",
            "3 | ⚙️ Set Server List Signature Key",
            "4 | ⚙️ Set Server List URL",
            "5 | ⚙️ Set Diagnostic Notices",
            "6 | ⚙️ Set Network Diagnostics"
        ]

        for item in menu_items:
            print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(40)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")

        print(f"{src_utils.BORDER_COLOR}╠{'═'*41}╣{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║ 0 | {src_utils.EXIT_STYLE}{'Back to Advanced Menu'.ljust(35)}{src_utils.RESET}{src_utils.BORDER_COLOR} ║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╚{'═'*41}╝{src_utils.RESET}")

        choice = input("\nEnter your choice: ").strip()

        if choice == "0":
            break

        elif choice == "1":
            parameters_visual_manager_Navigator(
                mode="text", key="PropagationChannelId"
            )
        elif choice == "2":
            parameters_visual_manager_Navigator(
                mode="text", key="SponsorId"
            )
        elif choice == "3":
            parameters_visual_manager_Navigator(
                mode="text", key="RemoteServerListSignaturePublicKey"
            )
        elif choice == "4":
            parameters_visual_manager_Navigator(
                mode="text", key="RemoteServerListUrl"
            )
        elif choice == "5":
            parameters_visual_manager_Navigator(
                mode="bool", key="EmitDiagnosticNotices"
            )
        elif choice == "6":
            parameters_visual_manager_Navigator(
                mode="bool", key="EmitDiagnosticNetworkParameters"
            )

        else:
            src_utils.warning("Invalid option selected", solution="Please choose from the list")
            input("Press Enter to continue...")





# -------------------------------------------------------------------------------
# ------------------------------ handler ------------------------------
# -------------------------------------------------------------------------------

def handle_psiphon_menu():
    while True:
        src_menus.display_psiphon_menu()
        
        choice = src_utils.get_user_input(f"\n{src_utils.HEADER_COLOR}Select an option : {src_utils.RESET}").strip()
        
        if choice == "0":
            src_utils.info("Returning to main menu...")
            break
        
        elif choice == '1':
            src_status.psiphon_status()
            input("\nPress Enter to return to Psiphon menu...")
            continue

        elif choice == "2":
            src_utils.clear_screen()
            src_utils.info("Starting Psiphon installer...")
            if not src_installer.install_psiphon():
                src_utils.error("❌ Psiphon installation failed.")

            input(f"\n{src_utils.YELLOW}Press Enter to continue...{src_utils.RESET}")
        

        elif choice == "3":  # Manual Configuration
            manual_config_psiphon()
            input(f"\n{src_utils.YELLOW}Press Enter to return to Psiphon menu...{src_utils.RESET}")


        elif choice == "4":
            display_advanced_psiphon_menu()
        
        elif choice == '5':  # Stop Psiphon
            src_utils.clear_screen()
            print("===============================================")
            print("               Stopping Psiphon")
            print("===============================================")
            stop_psiphon()
            input("\nPress Enter to return to Psiphon menu...")

        elif choice == '6':  # Restart Psiphon
            src_utils.clear_screen()
            print("===============================================")
            print("              Restarting Psiphon")
            print("===============================================")
            restart_psiphon()
            input("\nPress Enter to return to Psiphon menu...")
        
        elif choice == "7":  # Remove Psiphon
            src_utils.clear_screen()
 
            print("===============================================")
            print("               Remove Psiphon")
            print("===============================================\n")
            confirm_remove = src_utils.get_confirmation(
                f"{src_utils.YELLOW}Warning: This will completely remove Psiphon and its configurations.\n"
                f"Do you want to proceed?{src_utils.RESET}"
                "\n(Press Enter|y for confirmation, or type 'n' or 'no' to cancel): "
            )
            if not confirm_remove:
                src_utils.warning("Removal aborted by user", solution="Re-run setup to try again")
                input("Press Enter to return to Psiphon menu...")
                continue

            src_utils.info("Removing Psiphon...", context="Starting uninstall process")
            src_remover.remove_psiphon()
            input("\nPress Enter to return to Psiphon Setup menu...")

        
        else:
            src_utils.error(
                "Invalid menu choice",
                solution="Select a valid number from the menu options.",
                details=f"Received: {choice}"
            )
            input("Press Enter to try again...")