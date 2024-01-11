# DomainCheckr

DomainCheckr is a Python script designed for efficiently checking the reputation of multiple IP addresses and domains using the VirusTotal and AbuseIPDB APIs. The script can generate HTML reports, providing a comprehensive overview of the checked addresses.

## Requirements

- Python 3
- Install required packages using `pip install -r requirements.txt`

## Usage

1. **Obtain API Keys:**
   - Obtain API keys for VirusTotal and AbuseIPDB.
   - Paste the API keys into separate text files in the `api-keys` folder, with one key per line.

2. **Multiple API Keys:**
   - You can use multiple API keys for both VirusTotal and AbuseIPDB. The script will cycle through them to manage API limits effectively.

3. **Multithreading:**
   - For improved performance, consider utilizing multithreading.
   - Note: If generating HTML reports, it is recommended to use a licensed API key, as CLI output may have issues with multithreading.

## Testing

The script includes sample values in the `target-list.txt` file for testing purposes.

## How to Run

Example command:

```bash
python3 tool.py -h
```

## Contribution Guidelines

We welcome contributions to enhance and improve DomainCheckr. If you would like to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and ensure that the code follows PEP 8 guidelines.
4. Submit a pull request.

Please make sure to follow a descriptive and clear commit message convention.

## License

This project is licensed under the [MIT License](LICENSE).
