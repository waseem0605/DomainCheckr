# DomainCheckr

This script allows you to efficiently check the reputation of multiple IP addresses and domains using the VirusTotal and AbuseIPDB APIs. It can generate HTML reports for a comprehensive overview.

## Requirements

- Python 3
- Install required packages using `pip install -r requirements.txt`

## Usage

1. Obtain API keys for VirusTotal and AbuseIPDB and paste them into separate text files in the `api-keys` folder, one key per line.
2. You can use multiple API keys; the script will cycle through them to manage API limits effectively.
3. For improved performance, consider utilizing multithreading. Note that a licensed API key is recommended for HTML report generation, as CLI output may have issues with multithreading.

## Testing

The script includes sample values in the `target-list.txt` file for testing purposes.

## How to Run

Example command:

```bash
python3 tool.py -h
```
