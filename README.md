# IMAP-RECON Documentation 🚀📧

## Overview

IMAP-RECON is a comprehensive IMAP (Internet Message Access Protocol) reconnaissance tool designed for penetration testers and security professionals. This tool automates the process of enumerating email servers, extracting valuable information from mailboxes, and organizing the data in a structured format for analysis.

## Features ✨

- **Server Connection Management**: Connect to IMAP servers with support for both plain IMAP and IMAP over SSL/TLS
- **Mailbox Enumeration**: Discover and list all available mailboxes/folders
- **Email Analysis**: Extract comprehensive metadata and content from emails
- **Attachment Extraction**: Automatically save all email attachments
- **User Intelligence Gathering**: Extract email addresses, usernames, domains, and names
- **Keyword Search**: Find emails containing specific keywords
- **Detailed Reporting**: Generate summary reports of findings

## Installation 🛠️

### Prerequisites

- Python 3.6+
- Required Python packages:
    - colorama

### Setup

1. Clone the repository:
```bash
git clone https://github.com/grunt-ar/imap-recon.git
cd imap-recon
```
2. Install colorama:
```bash
pip install colorama
```

## Usage 📖

### Basic Usage

```bash
python imap-recon.py -H <host> -p <port> -u <username> -P <password>
```

### Command Line Arguments

| Argument | Long Form | Description | Required | Default |
|----------|-----------|-------------|----------|---------|
| `-H` | `--host` | IMAP server hostname or IP | Yes | - |
| `-p` | `--port` | IMAP server port | No | 143 |
| `-u` | `--username` | Username for authentication | Yes | - |
| `-P` | `--password` | Password for authentication | Yes | - |
| `-s` | `--ssl` | Use SSL/TLS | No | False |
| `-o` | `--output` | Output directory | No | imap_recon_output |
| `-k` | `--keywords` | Keywords to search for | No | - |
| `-v` | `--verbose` | Enable verbose output | No | False |

---

## Contributing 🤝

We welcome contributions! Feel free to submit pull requests or open issues to improve this project.

## Issues 🐛

If you encounter any bugs or have feature requests, please [open an issue](https://github.com/grunt-ar/imap-recon/issues). Your feedback is greatly appreciated!