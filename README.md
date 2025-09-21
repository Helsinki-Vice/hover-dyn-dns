# Hover DNS Update Script

This project is a fork of pjslauta's Python script for updating DNS records on Hover.

## Dependencies

- Python 3.x
- `requests` library

## Setup Instructions

### 1. Disable Email 2FA

In your hover.com account settings, disable "two-step sign in" authentication via email. Immediately re-enable it, but choose app authentication instead. Save the hexadecimal code `xxxx xxxx xxxx xxxx xxxx xxxx xx`, as this script requires it.

### 2. Clone the Repository

```sh
git clone https://github.com/Helsinki-Vice/hover-dyn-dns.git
cd hover-dyn-dns
```

### 3. Read the Arguments

```sh
python3 . --help
```

### 4. Run It

Use your hover.com username and password, plus the OTP secret from step 1.
```sh
python3 . --username you --password password1234 --totp_secret "xxxx xxxx xxxx xxxx xxxx xxxx xx" --domain example.com --host @,www,mail --type A,AAAA
```

### Put it in Crontab

```sh
crontab -e
```
This will open a text editor (Probably VIM, search for instructions). Add the following line to run evey five minutes:
```sh
*/5 * * * * python3 /path/to/hover-dyn-dns --username you --password password1234 --totp_secret "xxxx xxxx xxxx xxxx xxxx xxxx xx" --domain example.com --host @,www,mail --type A,AAAA
```
## Contributing

This project is licensed under the MIT License, see the `LICENSE` file for details. Contributions are welcome! Please open an issue or submit a pull request on GitHub. For any questions or issues, please contact [sean@sean-lauritzen.net](mailto:sean@sean-lauritzen.net).