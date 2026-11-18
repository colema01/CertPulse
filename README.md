
# CertPulse

CertPulse is a Python-based certificate monitoring tool I built to make it easier to find and track SSL/TLS certificates across a network.

The idea came from working in an enterprise environment where certificates were spread across hundreds of servers and services. Keeping track of expiration dates, certificate issuers, and which systems were using which certificates was more difficult than it needed to be.

CertPulse helps solve that by scanning IP addresses and network ranges, collecting certificate information, and displaying everything in a simple dashboard.

## Features

- **Network Scanning:** Scan individual IP addresses or entire CIDR ranges for SSL/TLS certificates.
- **Certificate Discovery:** Collect certificate details, including expiration dates, issuers, and subject information.
- **Expiration Tracking:** Identify certificates expiring within 30, 60, or 90 days.
- **Dashboard:** View discovered certificates and their expiration status in one place.
- **Certificate Storage:** Store discovered certificate information in a local database for tracking.
- **CSV Export:** Export certificate information to a CSV file for reporting or further analysis.
- **Custom Ports:** Scan HTTPS and other ports that use TLS.
- **Concurrent Scanning:** Scan multiple IP addresses concurrently while limiting the number of active scans.

## How It Works

CertPulse connects to the specified IP addresses and ports and attempts to retrieve the SSL/TLS certificate presented by each service.

If a certificate is found, CertPulse collects its information and stores the results locally. The dashboard then displays the certificates and highlights those that are approaching expiration.

The scanning process is limited to four IP addresses at a time to help avoid overwhelming the network or the systems being scanned.

## Why I Built It

I wanted a way to get better visibility into certificates without having to manually connect to individual servers or maintain spreadsheets.

Expired certificates can cause outages, authentication failures, and other problems that are usually avoidable with better tracking.

This project started as a way to make certificate management easier in the environments I work with, while also giving me an opportunity to build something useful with Python.

## Technologies

- Python
- pywebview
- SSL/TLS certificate inspection
- Local database storage
- PyInstaller for executable packaging

## Usage

CertPulse supports scanning individual IP addresses and CIDR ranges.

Once a scan is completed, the results can be viewed through the dashboard or exported to CSV.

The dashboard provides a quick way to identify certificates that need attention based on their expiration dates.

## Notes

CertPulse is intended for internal network visibility and certificate management. Only scan networks and systems you own or have permission to assess.

This is a personal project that I plan to continue improving as I find additional features worth adding.

## Disclaimer

CertPulse is provided as-is. It is not intended to replace a full enterprise certificate lifecycle management solution.
