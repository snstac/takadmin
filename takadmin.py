#!/usr/bin/env python3
"""
TAK Server User Management CLI Tool

A command-line tool for creating and managing TAK Server users via the REST API.
This tool follows the same design patterns as the web application.

Authentication:
- TAK Servers typically REQUIRE client certificate authentication (mutual TLS)
- Use --client-cert and --client-key to provide your client certificate
- If your private key is encrypted, use --client-key-password or you'll be prompted
- Username/password authentication (--admin-user) usually does NOT work alone
- Client certificates must be issued/signed by the TAK Server's Certificate Authority

SSL/TLS Configuration:
- By default, server certificate validation is DISABLED
- This allows connections to TAK Servers with self-signed or invalid certificates
- No truststore is required for basic operation
- Use --verify-ssl or --ca-bundle to enable certificate verification if needed
- Use --legacy-ssl for older servers that require TLS 1.0/1.1 or legacy ciphers

Reference API endpoints:
- POST /user-management/api/new-user - Create a single user
- POST /user-management/api/new-users - Bulk create users
- GET /user-management/api/list-users - List all users
- GET /user-management/api/get-groups-for-user/{username} - Get user groups
- PUT /user-management/api/change-user-password - Change user password
- PUT /user-management/api/update-groups - Update user groups
- DELETE /user-management/api/delete-user/{username} - Delete user
"""

import argparse
import getpass
import json
import os
import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import ssl
import sys
import tempfile
import urllib3
from typing import List, Optional
import random
import string

# Disable SSL warnings for self-signed certificates (common in TAK Server deployments)
# This allows connections to servers with invalid/self-signed certificates without warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LegacySSLAdapter(HTTPAdapter):
    """Custom HTTPAdapter that supports legacy SSL/TLS protocols for older servers"""
    
    def __init__(self, verify_ssl=False, *args, **kwargs):
        """
        Initialize the adapter
        
        Args:
            verify_ssl: Whether to verify SSL certificates
        """
        self.verify_ssl = verify_ssl
        super().__init__(*args, **kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        """Create a pool manager with a custom SSL context that allows legacy protocols"""
        # Create SSL context that supports legacy protocols
        ctx = create_urllib3_context()
        
        # Disable hostname checking when not verifying certificates
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        # Allow legacy protocols (TLS 1.0, TLS 1.1) and weaker ciphers
        # This is typically needed for older TAK Server deployments
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        
        # Set minimum TLS version to TLS 1.0 (instead of default 1.2)
        # Note: This may not work on all Python versions/platforms
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        except AttributeError:
            # Fallback for older Python versions
            ctx.options &= ~ssl.OP_NO_TLSv1
            ctx.options &= ~ssl.OP_NO_TLSv1_1
        
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


class PasswordGenerator:
    """Password generation utility matching TAK Server requirements"""
    
    SPECIAL_CHARS = "-_!@#$%^&+=~|:;,.?"
    
    @staticmethod
    def is_valid_password(password: str) -> bool:
        """
        Validate password meets TAK Server complexity requirements:
        - Minimum 15 characters
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 1 number
        - At least 1 special character from: -_!@#$%^&*(){}[]+=~`|:;<>,./?
        - No single or double quotes
        - No whitespace
        """
        if not password or len(password) < 15:
            return False
        
        # Check for required character types
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[-_!@#$%^&*(){}+=~`|:;<>,./?.\[\]\\]', password))
        has_quote = bool(re.search(r"['\"]", password))
        has_whitespace = bool(re.search(r'\s', password))
        
        return (has_upper and has_lower and has_digit and has_special and 
                not has_quote and not has_whitespace)
    
    @staticmethod
    def generate_password() -> str:
        """Generate a random password meeting TAK Server requirements"""
        upper = ''.join(random.choices(string.ascii_uppercase, k=3))
        lower = ''.join(random.choices(string.ascii_lowercase, k=3))
        digits = ''.join(random.choices(string.digits, k=3))
        alphanumeric = ''.join(random.choices(string.ascii_letters + string.digits, k=3))
        special = ''.join(random.choices(PasswordGenerator.SPECIAL_CHARS, k=3))
        
        combined = list(upper + lower + digits + alphanumeric + special)
        random.shuffle(combined)
        return ''.join(combined)


class UsernameValidator:
    """Username validation utility matching TAK Server requirements"""
    
    ERROR_MESSAGE = "Username is invalid. Username requirements: minimum of 4 characters and contains only letters, numbers, dots, underscores and hyphens."
    
    @staticmethod
    def is_valid_username(username: str) -> bool:
        """
        Validate username meets TAK Server requirements:
        - Minimum 4 characters
        - Only letters, numbers, dots, underscores, and hyphens
        """
        if not username or len(username) < 4:
            return False
        return bool(re.match(r'^[a-zA-Z0-9_.\-]+$', username))


class TAKUserManager:
    """TAK Server User Management API Client"""
    
    def __init__(self, base_url: str, username: Optional[str] = None, password: Optional[str] = None, 
                 verify_ssl: bool = False, client_cert: Optional[str] = None, 
                 client_key: Optional[str] = None, client_key_password: Optional[str] = None,
                 ca_bundle: Optional[str] = None, use_legacy_ssl: bool = False):
        """
        Initialize the TAK User Manager client
        
        Args:
            base_url: Base URL of the TAK Server (e.g., https://takserver.example.com:8443)
            username: Admin username for authentication (optional if using client cert)
            password: Admin password for authentication (optional if using client cert)
            verify_ssl: Whether to verify SSL certificates (default: False for self-signed certs)
            client_cert: Path to client certificate file for TLS authentication
            client_key: Path to client key file for TLS authentication (optional if key is in cert file)
            client_key_password: Password for encrypted private key file (will decrypt key)
            ca_bundle: Path to CA bundle file for verifying server certificate (optional)
            use_legacy_ssl: Enable legacy SSL/TLS protocols (TLS 1.0, 1.1) and weaker ciphers for older servers
        """
        self.base_url = base_url.rstrip('/')
        self.api_base = f"{self.base_url}/user-management/api"
        self.session = requests.Session()
        self._temp_key_file = None  # Track temporary decrypted key file
        
        # Configure authentication
        if client_cert:
            # Use client certificate authentication
            if client_key:
                # Handle encrypted private key
                key_to_use = client_key
                if client_key_password:
                    key_to_use = self._decrypt_private_key(client_key, client_key_password)
                self.session.cert = (client_cert, key_to_use)
            else:
                self.session.cert = client_cert
        elif username and password:
            # Use basic authentication
            self.session.auth = (username, password)
        else:
            raise ValueError("Either username/password or client_cert must be provided")
        
        # Configure SSL verification
        # By default, SSL verification is DISABLED to allow connections to servers
        # with self-signed or invalid certificates (common in TAK deployments)
        # Priority: ca_bundle > verify_ssl flag > False (default)
        if ca_bundle:
            self.session.verify = ca_bundle
        elif verify_ssl:
            self.session.verify = True
        else:
            # Explicitly disable certificate verification
            # This allows connecting without a truststore
            self.session.verify = False
        
        self.session.headers.update({'Content-Type': 'application/json'})
        
        # Validate client cert file exists if provided
        if client_cert and not os.path.exists(client_cert):
            raise FileNotFoundError(f"Client certificate file not found: {client_cert}")
        if client_key and not os.path.exists(client_key):
            raise FileNotFoundError(f"Client key file not found: {client_key}")
        
        # Mount legacy SSL adapter if requested (for older TAK servers)
        if use_legacy_ssl:
            # Pass the verify_ssl setting to the adapter so it can configure SSL context properly
            verify_setting = ca_bundle if ca_bundle else verify_ssl
            self.session.mount('https://', LegacySSLAdapter(verify_ssl=verify_setting))
    
    def _decrypt_private_key(self, key_path: str, password: str) -> str:
        """
        Decrypt an encrypted private key and return path to temporary decrypted key.
        
        Args:
            key_path: Path to encrypted private key file
            password: Password to decrypt the key
            
        Returns:
            Path to temporary decrypted key file
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            # Read encrypted key
            with open(key_path, 'rb') as f:
                encrypted_key = f.read()
            
            # Load and decrypt the key
            private_key = serialization.load_pem_private_key(
                encrypted_key,
                password=password.encode(),
                backend=default_backend()
            )
            
            # Serialize decrypted key to PEM format
            decrypted_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Write to temporary file
            temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem')
            temp_file.write(decrypted_pem)
            temp_file.close()
            
            self._temp_key_file = temp_file.name
            return temp_file.name
            
        except ImportError:
            raise ImportError(
                "The 'cryptography' library is required to use encrypted private keys. \n"
                "Install it with: pip install cryptography"
            )
        except Exception as e:
            raise ValueError(f"Failed to decrypt private key: {e}")
    
    def __del__(self):
        """Clean up temporary decrypted key file if it exists"""
        if self._temp_key_file and os.path.exists(self._temp_key_file):
            try:
                os.unlink(self._temp_key_file)
            except:
                pass
    
    def create_user(self, username: str, password: str, 
                   groups: Optional[List[str]] = None,
                   groups_in: Optional[List[str]] = None,
                   groups_out: Optional[List[str]] = None) -> dict:
        """
        Create a single user
        
        Args:
            username: Username for the new user
            password: Password for the new user
            groups: List of groups (both IN and OUT)
            groups_in: List of IN groups
            groups_out: List of OUT groups
            
        Returns:
            Response from the server
        """
        # Validate username
        if not UsernameValidator.is_valid_username(username):
            raise ValueError(UsernameValidator.ERROR_MESSAGE)
        
        # Validate password
        if not PasswordGenerator.is_valid_password(password):
            raise ValueError("Password complexity check failed. Password must be a minimum of 15 characters including 1 uppercase, 1 lowercase, 1 number, and 1 special character from this list [-_!@#$%^&*(){}[]+=~`|:;<>,./?].")
        
        payload = {
            "username": username,
            "password": password,
            "groupList": groups or [],
            "groupListIN": groups_in or [],
            "groupListOUT": groups_out or []
        }
        
        response = self.session.post(f"{self.api_base}/new-user", json=payload)
        response.raise_for_status()
        return {"success": True, "message": f"User '{username}' created successfully"}
    
    def create_users_bulk(self, username_pattern: str, start_n: int, end_n: int,
                         groups: Optional[List[str]] = None,
                         groups_in: Optional[List[str]] = None,
                         groups_out: Optional[List[str]] = None) -> List[dict]:
        """
        Create users in bulk using a pattern
        
        Args:
            username_pattern: Pattern with [N] placeholder (e.g., "user-[N]")
            start_n: Starting number
            end_n: Ending number
            groups: List of groups (both IN and OUT)
            groups_in: List of IN groups
            groups_out: List of OUT groups
            
        Returns:
            List of created users with their passwords
        """
        if "[N]" not in username_pattern:
            raise ValueError("Username pattern must contain [N] placeholder")
        
        payload = {
            "usernameExpression": username_pattern,
            "startN": start_n,
            "endN": end_n,
            "groupList": groups or [],
            "groupListIN": groups_in or [],
            "groupListOUT": groups_out or []
        }
        
        response = self.session.post(f"{self.api_base}/new-users", json=payload)
        response.raise_for_status()
        return response.json()
    
    def list_users(self) -> List[str]:
        """List all users"""
        response = self.session.get(f"{self.api_base}/list-users")
        response.raise_for_status()
        users = response.json()
        return [user['username'] for user in users]
    
    def get_user_groups(self, username: str) -> dict:
        """Get groups for a specific user"""
        response = self.session.get(f"{self.api_base}/get-groups-for-user/{username}")
        response.raise_for_status()
        return response.json()
    
    def change_password(self, username: str, password: str) -> dict:
        """Change user password"""
        if not PasswordGenerator.is_valid_password(password):
            raise ValueError("Password complexity check failed. Password must be a minimum of 15 characters including 1 uppercase, 1 lowercase, 1 number, and 1 special character from this list [-_!@#$%^&*(){}[]+=~`|:;<>,./?].")
        
        payload = {
            "username": username,
            "password": password
        }
        
        response = self.session.put(f"{self.api_base}/change-user-password", json=payload)
        response.raise_for_status()
        return {"success": True, "message": f"Password changed for user '{username}'"}
    
    def update_groups(self, username: str,
                     groups: Optional[List[str]] = None,
                     groups_in: Optional[List[str]] = None,
                     groups_out: Optional[List[str]] = None) -> dict:
        """Update user groups"""
        payload = {
            "username": username,
            "groupList": groups or [],
            "groupListIN": groups_in or [],
            "groupListOUT": groups_out or []
        }
        
        response = self.session.put(f"{self.api_base}/update-groups", json=payload)
        response.raise_for_status()
        return {"success": True, "message": f"Groups updated for user '{username}'"}
    
    def delete_user(self, username: str) -> dict:
        """Delete a user"""
        response = self.session.delete(f"{self.api_base}/delete-user/{username}")
        response.raise_for_status()
        return {"success": True, "message": f"User '{username}' deleted"}


def main():
    parser = argparse.ArgumentParser(
        description='TAK Server User Management CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a single user with client certificate authentication (RECOMMENDED)
  %(prog)s --url https://takserver:8443 --client-cert admin.pem --client-key admin-key.pem \\
    create-user --username john.doe --generate-password --groups group1
  
  # If cert and key are in same file
  %(prog)s --url https://takserver:8443 --client-cert admin.pem \\
    create-user --username john.doe --generate-password --groups group1
  
  # With encrypted private key (will prompt for password)
  %(prog)s --url https://takserver:8443 --client-cert admin.pem --client-key admin-key.pem \\
    list-users
  
  # With encrypted private key (password provided)
  %(prog)s --url https://takserver:8443 --client-cert admin.pem --client-key admin-key.pem \\
    --client-key-password "myKeyPass123" list-users
  
  # Create a single user with password and groups
  %(prog)s --url https://takserver:8443 --admin-user admin create-user \\
    --username john.doe --password "MyP@ssw0rd12345" --groups group1 group2
  
  # Create users in bulk
  %(prog)s --url https://takserver:8443 --admin-user admin bulk-create \\
    --pattern "user-[N]" --start 1 --end 10 --groups team1
  
  # List all users
  %(prog)s --url https://takserver:8443 --admin-user admin list-users
  
  # Get user groups
  %(prog)s --url https://takserver:8443 --admin-user admin get-groups --username john.doe
  
  # Change password
  %(prog)s --url https://takserver:8443 --admin-user admin change-password --username john.doe
  
  # Update groups
  %(prog)s --url https://takserver:8443 --admin-user admin update-groups \\
    --username john.doe --groups group1 --groups-in group2 --groups-out group3
  
  # Delete user
  %(prog)s --url https://takserver:8443 --admin-user admin delete-user --username john.doe
  
  # Connect to older TAK server with legacy SSL/TLS protocols
  %(prog)s --url https://oldserver:8443 --client-cert admin.pem --legacy-ssl list-users
  
  # Generate a valid password
  %(prog)s generate-password
        """
    )
    
    # Global arguments
    parser.add_argument('--url', help='TAK Server base URL (e.g., https://takserver:8443)')
    parser.add_argument('--admin-user', help='Admin username for basic authentication (WARNING: Most TAK Servers require --client-cert)')
    parser.add_argument('--admin-password', help='Admin password (will prompt if not provided)')
    parser.add_argument('--client-cert', required=False, help='Path to client certificate file for TLS authentication (RECOMMENDED: TAK Servers typically require this)')
    parser.add_argument('--client-key', help='Path to client key file (optional if key is in cert file)')
    parser.add_argument('--client-key-password', help='Password for encrypted private key file (will prompt if not provided and key is encrypted)')
    parser.add_argument('--verify-ssl', action='store_true', 
                       help='Enable server SSL certificate verification (default: DISABLED - allows connecting to servers with self-signed/invalid certs without a truststore)')
    parser.add_argument('--ca-bundle', help='Path to CA bundle/truststore file for verifying server certificate (e.g., truststore-root.pem). When specified, enables SSL verification.')
    parser.add_argument('--legacy-ssl', action='store_true',
                       help='Enable legacy SSL/TLS protocols (TLS 1.0, 1.1) and weaker ciphers for older TAK servers')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Create user command
    create_parser = subparsers.add_parser('create-user', help='Create a single user')
    create_parser.add_argument('--username', required=True, help='Username for the new user')
    create_parser.add_argument('--password', help='Password (will prompt if not provided)')
    create_parser.add_argument('--groups', nargs='*', default=[], help='Groups (both IN and OUT)')
    create_parser.add_argument('--groups-in', nargs='*', default=[], help='IN groups')
    create_parser.add_argument('--groups-out', nargs='*', default=[], help='OUT groups')
    create_parser.add_argument('--generate-password', action='store_true', 
                              help='Generate a random password meeting requirements')
    
    # Bulk create command
    bulk_parser = subparsers.add_parser('bulk-create', help='Create users in bulk')
    bulk_parser.add_argument('--pattern', required=True, 
                            help='Username pattern with [N] placeholder (e.g., "user-[N]")')
    bulk_parser.add_argument('--start', type=int, required=True, help='Starting number')
    bulk_parser.add_argument('--end', type=int, required=True, help='Ending number')
    bulk_parser.add_argument('--groups', nargs='*', default=[], help='Groups (both IN and OUT)')
    bulk_parser.add_argument('--groups-in', nargs='*', default=[], help='IN groups')
    bulk_parser.add_argument('--groups-out', nargs='*', default=[], help='OUT groups')
    bulk_parser.add_argument('--output', help='Output file for user/password list (JSON format)')
    
    # List users command
    subparsers.add_parser('list-users', help='List all users')
    
    # Get user groups command
    groups_parser = subparsers.add_parser('get-groups', help='Get groups for a user')
    groups_parser.add_argument('--username', required=True, help='Username')
    
    # Change password command
    passwd_parser = subparsers.add_parser('change-password', help='Change user password')
    passwd_parser.add_argument('--username', required=True, help='Username')
    passwd_parser.add_argument('--password', help='New password (will prompt if not provided)')
    passwd_parser.add_argument('--generate-password', action='store_true',
                              help='Generate a random password meeting requirements')
    
    # Update groups command
    update_groups_parser = subparsers.add_parser('update-groups', help='Update user groups')
    update_groups_parser.add_argument('--username', required=True, help='Username')
    update_groups_parser.add_argument('--groups', nargs='*', default=[], help='Groups (both IN and OUT)')
    update_groups_parser.add_argument('--groups-in', nargs='*', default=[], help='IN groups')
    update_groups_parser.add_argument('--groups-out', nargs='*', default=[], help='OUT groups')
    
    # Delete user command
    delete_parser = subparsers.add_parser('delete-user', help='Delete a user')
    delete_parser.add_argument('--username', required=True, help='Username')
    
    # Generate password command
    subparsers.add_parser('generate-password', help='Generate a valid password')
    
    args = parser.parse_args()
    
    # Handle generate-password without requiring server connection
    if args.command == 'generate-password':
        password = PasswordGenerator.generate_password()
        print(f"Generated password: {password}")
        return 0
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Validate required arguments for server commands
    if not args.url:
        print("Error: --url is required", file=sys.stderr)
        return 1
    
    # Check authentication method
    if not args.client_cert and not args.admin_user:
        print("Error: Either --admin-user or --client-cert is required", file=sys.stderr)
        return 1
    
    # Warn if using username/password without client cert (TAK servers typically require client certs)
    if args.admin_user and not args.client_cert:
        print("WARNING: Using username/password authentication without client certificate.", file=sys.stderr)
        print("WARNING: Most TAK Servers require client certificate authentication (mutual TLS).", file=sys.stderr)
        print("WARNING: If connection fails with 'bad certificate' error, you need --client-cert.", file=sys.stderr)
        print("", file=sys.stderr)
    
    # Get admin password if using username/password auth
    admin_password = None
    if args.admin_user and not args.client_cert:
        admin_password = args.admin_password
        if not admin_password:
            admin_password = getpass.getpass(f"Enter password for admin user '{args.admin_user}': ")
    
    # Get client key password if needed
    client_key_password = None
    if args.client_key and args.client_key_password:
        client_key_password = args.client_key_password
    elif args.client_key:
        # Check if key is encrypted by trying to read it
        try:
            with open(args.client_key, 'r') as f:
                key_content = f.read()
                if 'ENCRYPTED' in key_content:
                    client_key_password = getpass.getpass(f"Enter password for encrypted private key: ")
        except:
            pass
    
    try:
        manager = TAKUserManager(
            args.url, 
            username=args.admin_user,
            password=admin_password, 
            verify_ssl=args.verify_ssl,
            client_cert=args.client_cert,
            client_key=args.client_key,
            client_key_password=client_key_password,
            ca_bundle=args.ca_bundle,
            use_legacy_ssl=args.legacy_ssl
        )
        
        if args.command == 'create-user':
            # Get or generate password
            password = args.password
            if args.generate_password:
                password = PasswordGenerator.generate_password()
                print(f"Generated password: {password}")
            elif not password:
                password = getpass.getpass(f"Enter password for user '{args.username}': ")
                confirm = getpass.getpass("Confirm password: ")
                if password != confirm:
                    print("Error: Passwords do not match", file=sys.stderr)
                    return 1
            
            result = manager.create_user(
                args.username, password,
                groups=args.groups,
                groups_in=args.groups_in,
                groups_out=args.groups_out
            )
            print(json.dumps(result, indent=2))
            
        elif args.command == 'bulk-create':
            result = manager.create_users_bulk(
                args.pattern, args.start, args.end,
                groups=args.groups,
                groups_in=args.groups_in,
                groups_out=args.groups_out
            )
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Created {len(result)} users. Credentials saved to {args.output}")
            else:
                print(json.dumps(result, indent=2))
            
        elif args.command == 'list-users':
            users = manager.list_users()
            print(f"Total users: {len(users)}")
            for user in sorted(users):
                print(f"  - {user}")
            
        elif args.command == 'get-groups':
            groups = manager.get_user_groups(args.username)
            print(json.dumps(groups, indent=2))
            
        elif args.command == 'change-password':
            password = args.password
            if args.generate_password:
                password = PasswordGenerator.generate_password()
                print(f"Generated password: {password}")
            elif not password:
                password = getpass.getpass(f"Enter new password for user '{args.username}': ")
                confirm = getpass.getpass("Confirm password: ")
                if password != confirm:
                    print("Error: Passwords do not match", file=sys.stderr)
                    return 1
            
            result = manager.change_password(args.username, password)
            print(json.dumps(result, indent=2))
            
        elif args.command == 'update-groups':
            result = manager.update_groups(
                args.username,
                groups=args.groups,
                groups_in=args.groups_in,
                groups_out=args.groups_out
            )
            print(json.dumps(result, indent=2))
            
        elif args.command == 'delete-user':
            result = manager.delete_user(args.username)
            print(json.dumps(result, indent=2))
        
        return 0
        
    except requests.exceptions.SSLError as e:
        print(f"Error: SSL/TLS connection failed: {e}", file=sys.stderr)
        print("\n" + "="*70, file=sys.stderr)
        print("TROUBLESHOOTING SSL ERRORS:", file=sys.stderr)
        print("="*70, file=sys.stderr)
        if "CERTIFICATE" in str(e).upper() or "BAD_CERTIFICATE" in str(e).upper():
            if args.client_cert:
                print("\n[Client Certificate Rejected]\n", file=sys.stderr)
                print("  The server rejected your client certificate. Possible causes:", file=sys.stderr)
                print(f"  ✗ Certificate not issued/signed by the TAK Server's CA", file=sys.stderr)
                print(f"  ✗ Certificate has expired", file=sys.stderr)
                print(f"  ✗ Certificate and private key don't match", file=sys.stderr)
                print(f"  ✗ Certificate file path incorrect: {args.client_cert}", file=sys.stderr)
                if args.client_key:
                    print(f"  ✗ Key file path incorrect: {args.client_key}", file=sys.stderr)
                print("\n  To generate a valid certificate:", file=sys.stderr)
                print("    - Use TAK Server's cert management tools", file=sys.stderr)
                print("    - Use CoreConfig or user-manager scripts", file=sys.stderr)
                print("    - Ensure certificate is signed by TAK Server's CA", file=sys.stderr)
            else:
                print("\n[Client Certificate Required]\n", file=sys.stderr)
                print("  TAK Server REQUIRES client certificate authentication (mutual TLS).", file=sys.stderr)
                print("  Username/password authentication alone is NOT sufficient.\n", file=sys.stderr)
                print("  SOLUTION: Obtain a client certificate and use:", file=sys.stderr)
                print(f"    python {sys.argv[0]} --url {args.url} \\", file=sys.stderr)
                print(f"      --client-cert /path/to/admin.pem \\", file=sys.stderr)
                print(f"      --client-key /path/to/admin-key.pem \\", file=sys.stderr)
                print(f"      {args.command}", file=sys.stderr)
                print("\n  How to get a client certificate:", file=sys.stderr)
                print("    - Contact your TAK Server administrator", file=sys.stderr)
                print("    - Use TAK Server's certificate generation tools", file=sys.stderr)
                print("    - Check TAK Server's /opt/tak/certs directory", file=sys.stderr)
        else:
            print(f"\n  Unexpected SSL error. Details: {str(e)}", file=sys.stderr)
        print(f"\nServer certificate validation: {'ENABLED' if args.verify_ssl or args.ca_bundle else 'DISABLED (default)'}", file=sys.stderr)
        print("="*70, file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except requests.exceptions.RequestException as e:
        print(f"Error: API request failed: {e}", file=sys.stderr)
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
