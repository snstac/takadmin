# TAK Server User Management CLI Tool

A command-line tool for creating and managing TAK Server users via the REST API. This tool follows the same design patterns and validation rules as the TAK Server web application.

## Features

- **Create single users** with username, password, and group assignments
- **Bulk create users** using username patterns (e.g., `user-[N]`)
- **List all users** in the system
- **View user groups** (IN, OUT, and both)
- **Change passwords** with complexity validation
- **Update group assignments** for existing users
- **Delete users**
- **Generate passwords** that meet TAK Server requirements
- Password and username validation matching server requirements

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

### Option 1: Install as a Command-Line Tool (Recommended)

Install directly from the repository:

```bash
pip install .
```

Or install in development mode (for developers):

```bash
pip install -e .
```

After installation, you can use the `takadmin` command from anywhere:

```bash
takadmin --help
```

### Option 2: Install from PyPI (if published)

```bash
pip install takadmin
```

### Option 3: Install Dependencies Only

If you prefer to run the script directly without installing:

```bash
pip install -r requirements.txt
python takadmin.py --help
```

### Upgrading

To upgrade to the latest version:

```bash
pip install --upgrade takadmin
```

### Uninstallation

To remove the tool:

```bash
pip uninstall takadmin
```

## Usage

### General Syntax

After installation, use the `takadmin` command:

```bash
takadmin --url <SERVER_URL> --admin-user <ADMIN_USERNAME> <COMMAND> [OPTIONS]
```

Or if running the script directly without installation:

```bash
python takadmin.py --url <SERVER_URL> --admin-user <ADMIN_USERNAME> <COMMAND> [OPTIONS]
```

The admin password will be prompted securely if not provided via `--admin-password`.

### Password Requirements

TAK Server enforces the following password complexity requirements:
- Minimum 15 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number
- At least 1 special character from: `-_!@#$%^&*(){}[]+=~`|:;<>,./?`
- No single or double quotes
- No whitespace

### Username Requirements

TAK Server enforces the following username requirements:
- Minimum 4 characters
- Only letters, numbers, dots, underscores, and hyphens

## Commands

### 1. Generate a Valid Password

Generate a random password meeting TAK Server requirements (no server connection needed):

```bash
takadmin generate-password
```

### 2. Create a Single User

Create a user interactively (prompts for passwords):

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  create-user --username john.doe
```

Create a user with explicit password:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  create-user --username john.doe --password "MyP@ssw0rd12345"
```

Create a user with auto-generated password:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  create-user --username john.doe --generate-password
```

Create a user with group assignments:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  create-user --username john.doe --generate-password \
  --groups __ANON__ \
  --groups-in team1 team2 \
  --groups-out public
```

**Group Types:**
- `--groups`: Groups for both IN and OUT
- `--groups-in`: Groups the user can read from
- `--groups-out`: Groups the user can write to

### 3. Bulk Create Users

Create multiple users using a pattern with `[N]` placeholder:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  bulk-create --pattern "user-[N]" --start 1 --end 10 \
  --groups __ANON__
```

Save credentials to a file:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  bulk-create --pattern "team-member-[N]" --start 1 --end 50 \
  --groups team1 --output users.json
```

The output file will contain a JSON array with username/password pairs:
```json
[
  {
    "username": "team-member-1",
    "password": "GeneratedPassword123!"
  },
  ...
]
```

### 4. List All Users

```bash
takadmin --url https://takserver:8443 --admin-user admin list-users
```

### 5. Get User Groups

View group assignments for a specific user:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  get-groups --username john.doe
```

### 6. Change User Password

Change password interactively:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  change-password --username john.doe
```

Change to a specific password:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  change-password --username john.doe --password "NewP@ssw0rd12345"
```

Generate and set a new random password:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  change-password --username john.doe --generate-password
```

### 7. Update User Groups

Update group assignments for an existing user:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  update-groups --username john.doe \
  --groups __ANON__ \
  --groups-in team1 team2 \
  --groups-out public
```

**Note:** This replaces all existing group assignments. Include all desired groups in the command.

### 8. Delete User

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  delete-user --username john.doe
```

## SSL Certificate Verification

By default, the tool does not verify SSL certificates (common for TAK Servers with self-signed certificates). To enable SSL verification:

```bash
takadmin --url https://takserver:8443 --admin-user admin \
  --verify-ssl list-users
```

## Examples

### Example 1: Onboarding a New Team

Create 20 users for a new team with shared groups:

```bash
takadmin --url https://takserver.example.com:8443 --admin-user admin \
  bulk-create --pattern "alpha-team-[N]" --start 1 --end 20 \
  --groups __ANON__ --groups-in ALPHA_TEAM \
  --output alpha-team-credentials.json
```

### Example 2: Creating a User with Full Permissions

```bash
takadmin --url https://takserver.example.com:8443 --admin-user admin \
  create-user --username field.operator \
  --generate-password \
  --groups __ANON__ \
  --groups-in MISSION_DATA BLUE_FORCE \
  --groups-out BLUE_FORCE
```

### Example 3: Password Reset

```bash
# Generate a new password and change it
takadmin --url https://takserver.example.com:8443 --admin-user admin \
  change-password --username john.doe --generate-password
```

### Example 4: Audit Users and Groups

```bash
# List all users
takadmin --url https://takserver.example.com:8443 --admin-user admin \
  list-users

# Check groups for specific user
takadmin --url https://takserver.example.com:8443 --admin-user admin \
  get-groups --username john.doe
```

## API Reference

This tool uses the following TAK Server REST API endpoints (as implemented in the web application):

- `POST /user-management/api/new-user` - Create a single user
- `POST /user-management/api/new-users` - Bulk create users  
- `GET /user-management/api/list-users` - List all users
- `GET /user-management/api/get-groups-for-user/{username}` - Get user groups
- `PUT /user-management/api/change-user-password` - Change user password
- `PUT /user-management/api/update-groups` - Update user groups
- `DELETE /user-management/api/delete-user/{username}` - Delete user

## Error Handling

The tool provides clear error messages for common issues:

- **Invalid username**: Minimum 4 characters, alphanumeric with dots, underscores, hyphens
- **Invalid password**: Must meet complexity requirements (15+ chars, mixed case, numbers, special chars)
- **User already exists**: Cannot create duplicate usernames
- **User not found**: Username doesn't exist for update/delete operations
- **Authentication failure**: Invalid admin credentials
- **Connection errors**: Server unavailable or incorrect URL

## Security Considerations

1. **Secure Password Input**: Passwords are prompted via `getpass` to avoid shell history
2. **HTTPS**: Always use HTTPS URLs for production servers
3. **Credentials Storage**: Store bulk creation output files securely
4. **Admin Access**: This tool requires admin credentials - protect them appropriately
5. **Password Complexity**: All passwords are validated against TAK Server requirements

## Troubleshooting

### Connection Refused

```
Error: API request failed: Connection refused
```

- Verify the server URL and port
- Ensure the TAK Server is running
- Check firewall rules

### Authentication Failed

```
Error: API request failed: 401 Unauthorized
```

- Verify admin username and password
- Ensure the admin user has appropriate permissions

### SSL Certificate Error

```
Error: SSL certificate verify failed
```

- Use `--verify-ssl` flag if you have proper certificates
- Or use the default (no verification) for self-signed certs

### Invalid Password

```
Error: Password complexity check failed
```

- Use `--generate-password` flag for compliant passwords
- Or manually create a password meeting all requirements

## Integration with TAK Server

This tool is designed to work with TAK Server's file-based authentication system. It interacts with the same REST API endpoints used by the web application interface, ensuring consistency with the web UI behavior.

The tool validates usernames and passwords using the same rules as the server (implemented in `UsernameUtils` and `PasswordUtils` classes), preventing invalid user creation attempts.

## License

This tool is part of the TAK Server project. See the main LICENSE file for details.
