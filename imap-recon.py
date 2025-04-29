#!/usr/bin/env python3
"""
IMAP Reconnaissance Tool

This tool performs comprehensive enumeration of IMAP mail servers,
retrieving mailboxes, emails, attachments, and other useful information.
"""

import argparse
import imaplib
import email
import email.header
import os
import sys
import re
import base64
import quopri
from datetime import datetime
from email.parser import BytesParser
from email.policy import default


# Class to handle IMAP reconnaissance
class ImapRecon:
    def __init__(self, host, port, username, password, ssl=False, output_dir=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.connection = None
        self.mailboxes = []
        self.output_dir = output_dir or 'imap_recon_output'
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Create directory for attachments
        self.attachments_dir = os.path.join(self.output_dir, 'attachments')
        if not os.path.exists(self.attachments_dir):
            os.makedirs(self.attachments_dir)

    def connect(self):
        """Establish connection to the IMAP server"""
        try:
            if self.ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port)
            
            print(f"[+] Connected to {self.host}:{self.port}")
            
            # Try to login
            self.connection.login(self.username, self.password)
            print(f"[+] Successfully logged in as {self.username}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {str(e)}")
            return False

    def list_mailboxes(self):
        """List all available mailboxes/folders"""
        try:
            status, mailboxes = self.connection.list()
            if status == 'OK':
                print("[+] Available mailboxes:")
                for mailbox in mailboxes:
                    # Decode mailbox name
                    decoded_mailbox = mailbox.decode('utf-8')
                    print(f"    {decoded_mailbox}")
                    self.mailboxes.append(decoded_mailbox)
                
                # Write mailboxes to file
                with open(os.path.join(self.output_dir, 'mailboxes.txt'), 'w') as f:
                    for mailbox in self.mailboxes:
                        f.write(f"{mailbox}\n")
                
                return True
            else:
                print("[-] Failed to list mailboxes")
                return False
        except Exception as e:
            print(f"[-] Error listing mailboxes: {str(e)}")
            return False

    def decode_header(self, header):
        """Decode email header"""
        decoded_header = email.header.decode_header(header)
        header_parts = []
        
        for part, encoding in decoded_header:
            if isinstance(part, bytes):
                try:
                    if encoding:
                        header_parts.append(part.decode(encoding))
                    else:
                        header_parts.append(part.decode('utf-8', errors='replace'))
                except:
                    header_parts.append(part.decode('utf-8', errors='replace'))
            else:
                header_parts.append(part)
        
        return ' '.join(header_parts)

    def get_email_content(self, msg):
        """Extract email content (text and HTML)"""
        content = {"text": "", "html": ""}
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        decoded_payload = payload.decode(charset, errors='replace')
                    except:
                        decoded_payload = payload.decode('utf-8', errors='replace')
                    
                    if content_type == 'text/plain':
                        content["text"] += decoded_payload
                    elif content_type == 'text/html':
                        content["html"] += decoded_payload
        else:
            # Not multipart - get the content directly
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                try:
                    decoded_payload = payload.decode(charset, errors='replace')
                except:
                    decoded_payload = payload.decode('utf-8', errors='replace')
                
                content_type = msg.get_content_type()
                if content_type == 'text/plain':
                    content["text"] = decoded_payload
                elif content_type == 'text/html':
                    content["html"] = decoded_payload
        
        return content

    def extract_attachments(self, msg, email_id, mailbox):
        """Extract and save email attachments"""
        attachments = []
        
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            
            filename = part.get_filename()
            if not filename:
                continue
            
            # Decode filename if needed
            filename = self.decode_header(filename)
            
            # Clean filename to avoid path traversal
            clean_filename = re.sub(r'[^\w\.-]', '_', filename)
            
            # Create directory for this email's attachments
            email_attachment_dir = os.path.join(self.attachments_dir, f"{mailbox.replace('/', '_')}_{email_id}")
            if not os.path.exists(email_attachment_dir):
                os.makedirs(email_attachment_dir)
            
            file_path = os.path.join(email_attachment_dir, clean_filename)
            
            # Save the attachment
            with open(file_path, 'wb') as f:
                f.write(part.get_payload(decode=True))
            
            attachments.append({
                "filename": filename,
                "path": file_path,
                "content_type": part.get_content_type()
            })
            
            print(f"    [+] Saved attachment: {filename}")
        
        return attachments

    def analyze_email(self, mailbox, email_id, msg):
        """Analyze an email and extract relevant information"""
        email_data = {
            "id": email_id,
            "mailbox": mailbox,
            "subject": self.decode_header(msg["Subject"] or ""),
            "from": self.decode_header(msg["From"] or ""),
            "to": self.decode_header(msg["To"] or ""),
            "cc": self.decode_header(msg["Cc"] or ""),
            "bcc": self.decode_header(msg["Bcc"] or ""),
            "date": self.decode_header(msg["Date"] or ""),
            "content": self.get_email_content(msg),
            "attachments": self.extract_attachments(msg, email_id, mailbox)
        }
        
        # Extract email addresses
        email_pattern = r'[\w\.-]+@[\w\.-]+'
        all_recipients = f"{email_data['to']} {email_data['cc']} {email_data['bcc']}"
        email_data["email_addresses"] = re.findall(email_pattern, f"{email_data['from']} {all_recipients}")
        
        return email_data

    def parse_emails(self, mailbox):
        """Parse all emails in a mailbox"""
        try:
            # Try to select the mailbox
            mailbox_name = mailbox.split(' ')[-1].strip('"')
            status, data = self.connection.select(mailbox_name)
            
            if status != 'OK':
                print(f"[-] Could not select mailbox: {mailbox_name}")
                return
            
            # Get the total number of emails
            email_count = int(data[0])
            print(f"[+] Found {email_count} emails in {mailbox_name}")
            
            if email_count == 0:
                return
            
            # Create directory for this mailbox's emails
            mailbox_dir = os.path.join(self.output_dir, mailbox_name.replace('/', '_'))
            if not os.path.exists(mailbox_dir):
                os.makedirs(mailbox_dir)
            
            # Search for all emails in the mailbox
            status, data = self.connection.search(None, 'ALL')
            if status != 'OK':
                print(f"[-] Failed to search emails in {mailbox_name}")
                return
            
            # Process each email
            email_ids = data[0].split()
            for email_id in email_ids:
                email_id_str = email_id.decode('utf-8')
                print(f"[+] Processing email ID: {email_id_str}")
                
                # Fetch the email data
                status, data = self.connection.fetch(email_id, '(RFC822)')
                if status != 'OK':
                    print(f"[-] Failed to fetch email ID: {email_id_str}")
                    continue
                
                # Parse the email
                raw_email = data[0][1]
                msg = email.message_from_bytes(raw_email, policy=default)
                
                # Analyze the email
                email_data = self.analyze_email(mailbox_name, email_id_str, msg)
                
                # Save the email data to a file
                email_file = os.path.join(mailbox_dir, f"email_{email_id_str}.txt")
                with open(email_file, 'w', encoding='utf-8') as f:
                    f.write(f"ID: {email_data['id']}\n")
                    f.write(f"Subject: {email_data['subject']}\n")
                    f.write(f"From: {email_data['from']}\n")
                    f.write(f"To: {email_data['to']}\n")
                    f.write(f"CC: {email_data['cc']}\n")
                    f.write(f"BCC: {email_data['bcc']}\n")
                    f.write(f"Date: {email_data['date']}\n")
                    f.write(f"Email Addresses: {', '.join(email_data['email_addresses'])}\n")
                    f.write("\n--- TEXT CONTENT ---\n")
                    f.write(email_data['content']['text'])
                    f.write("\n\n--- HTML CONTENT ---\n")
                    f.write(email_data['content']['html'])
                    f.write("\n\n--- ATTACHMENTS ---\n")
                    for attachment in email_data['attachments']:
                        f.write(f"Filename: {attachment['filename']}\n")
                        f.write(f"Path: {attachment['path']}\n")
                        f.write(f"Content-Type: {attachment['content_type']}\n\n")
                
                # Save the raw email
                raw_email_file = os.path.join(mailbox_dir, f"raw_email_{email_id_str}.eml")
                with open(raw_email_file, 'wb') as f:
                    f.write(raw_email)
                
                print(f"    [+] Saved email data to {email_file}")
                print(f"    [+] Saved raw email to {raw_email_file}")

        except Exception as e:
            print(f"[-] Error processing mailbox {mailbox_name}: {str(e)}")

    def extract_user_info(self):
        """Extract user information from emails"""
        user_info = {
            "usernames": set(),
            "email_addresses": set(),
            "domains": set(),
            "names": set()
        }
        
        # Regular expressions
        email_pattern = r'[\w\.-]+@[\w\.-]+'
        domain_pattern = r'@([\w\.-]+)'
        name_pattern = r'"([^"]+)"'
        
        # Walk through all the output files
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.startswith("email_") and file.endswith(".txt"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Extract email addresses
                            emails = re.findall(email_pattern, content)
                            for email_addr in emails:
                                user_info["email_addresses"].add(email_addr)
                                user_info["usernames"].add(email_addr.split('@')[0])
                            
                            # Extract domains
                            domains = re.findall(domain_pattern, content)
                            for domain in domains:
                                user_info["domains"].add(domain)
                            
                            # Extract names
                            names = re.findall(name_pattern, content)
                            for name in names:
                                user_info["names"].add(name)
                    except Exception as e:
                        print(f"[-] Error processing {file_path}: {str(e)}")
        
        # Save user information to files
        for info_type, items in user_info.items():
            output_file = os.path.join(self.output_dir, f"{info_type}.txt")
            with open(output_file, 'w', encoding='utf-8') as f:
                for item in sorted(items):
                    f.write(f"{item}\n")
            
            print(f"[+] Extracted {len(items)} {info_type}")
        
        return user_info

    def search_keywords(self, keywords):
        """Search for specific keywords in emails"""
        results = {}
        
        for keyword in keywords:
            results[keyword] = []
            
            # Walk through all the output files
            for root, dirs, files in os.walk(self.output_dir):
                for file in files:
                    if file.startswith("email_") and file.endswith(".txt"):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if re.search(r'\b' + re.escape(keyword) + r'\b', content, re.IGNORECASE):
                                    results[keyword].append(file_path)
                        except Exception as e:
                            print(f"[-] Error searching in {file_path}: {str(e)}")
        
        # Save search results to file
        output_file = os.path.join(self.output_dir, "search_results.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            for keyword, file_paths in results.items():
                f.write(f"Keyword: {keyword}\n")
                f.write(f"Found in {len(file_paths)} files:\n")
                for file_path in file_paths:
                    f.write(f"  {file_path}\n")
                f.write("\n")
        
        print(f"[+] Search results saved to {output_file}")
        return results

    def create_summary(self):
        """Create a summary of the reconnaissance"""
        summary = {
            "server": f"{self.host}:{self.port}",
            "username": self.username,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mailboxes": len(self.mailboxes),
            "emails": 0,
            "attachments": 0
        }
        
        # Count emails and attachments
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.startswith("email_") and file.endswith(".txt"):
                    summary["emails"] += 1
        
        for root, dirs, files in os.walk(self.attachments_dir):
            for file in files:
                if not file.startswith("."):
                    summary["attachments"] += 1
        
        # Save summary to file
        output_file = os.path.join(self.output_dir, "summary.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("IMAP Reconnaissance Summary\n")
            f.write("=========================\n\n")
            f.write(f"Server: {summary['server']}\n")
            f.write(f"Username: {summary['username']}\n")
            f.write(f"Timestamp: {summary['timestamp']}\n")
            f.write(f"Mailboxes: {summary['mailboxes']}\n")
            f.write(f"Emails: {summary['emails']}\n")
            f.write(f"Attachments: {summary['attachments']}\n")
        
        print(f"[+] Summary saved to {output_file}")
        return summary

    def run(self, keywords=None):
        """Run the complete reconnaissance process"""
        print("[*] Starting IMAP reconnaissance")
        
        # Connect to the server
        if not self.connect():
            return False
        
        # List mailboxes
        self.list_mailboxes()
        
        # Extract mailbox names from the response
        mailbox_pattern = r'"\/" (.+)'
        for mailbox in self.mailboxes:
            match = re.search(mailbox_pattern, mailbox)
            if match:
                mailbox_name = match.group(1)
                self.parse_emails(mailbox_name)
            else:
                # Try to parse emails directly from the raw mailbox string
                self.parse_emails(mailbox)
        
        # Extract user information
        self.extract_user_info()
        
        # Search for keywords if provided
        if keywords:
            self.search_keywords(keywords)
        
        # Create summary
        self.create_summary()
        
        # Logout
        self.connection.logout()
        print("[*] IMAP reconnaissance completed")
        return True


def main():
    parser = argparse.ArgumentParser(description='IMAP Reconnaissance Tool')
    parser.add_argument('-H', '--host', required=True, help='IMAP server hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=143, help='IMAP server port (default: 143)')
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-P', '--password', required=True, help='Password')
    parser.add_argument('-s', '--ssl', action='store_true', help='Use SSL/TLS')
    parser.add_argument('-o', '--output', help='Output directory (default: imap_recon_output)')
    parser.add_argument('-k', '--keywords', nargs='+', help='Keywords to search for in emails')
    
    args = parser.parse_args()
    
    # Initialize the ImapRecon class
    recon = ImapRecon(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        ssl=args.ssl,
        output_dir=args.output
    )
    
    # Run reconnaissance
    recon.run(keywords=args.keywords)


if __name__ == "__main__":
    main()