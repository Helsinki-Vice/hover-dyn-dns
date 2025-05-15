# Hover DNS Update Script

This project is a Python script for updating DNS records on Hover. It supports optional logging and the use of `mitmproxy` for debugging HTTP/HTTPS requests.

## Dependencies

- Python 3.x
- `requests` library
- `mitmproxy` (optional, for debugging)

## Setup Instructions

### 1. Disable Email 2FA

In your hover.com account settings, disable "two-step sign in" authentication via email. Immediately re-enable it, but choose app authentication instead. Save the hexadecimal code `xxxx xxxx xxxx xxxx xxxx xxxx xx`, as this script requires it.

### 2. Clone the Repository

```sh
git clone <repository_url>
cd <repository_directory>
```

### 3. Install Python Dependencies

Install the required Python libraries using `pip`:

```sh
pip install requests
```

### 4. Install `mitmproxy` (Optional)

`mitmproxy` is used for debugging HTTP/HTTPS requests. To install `mitmproxy`, run:

```sh
pip install mitmproxy
```

### 5. Create Configuration Files

Create the following configuration files:

#### `config.json`

Create a `config.json` file in the project directory with the following content:

```json
{
    "username": "<your_hover_username>",
    "password": "<password>",
    "domain": "your-domain.net",
    "subdomain": null,
    "totp_secret": "xxxx xxxx xxxx xxxx xxxx xxxx xx"
}
```

Replace the placeholders with your actual values. the TOTP secret is the authenticator app code from earlier.

## Usage Instructions

### Running the Script

To run the script, use the following command:

```sh
python3 . [--logging] [--mitm]
```

#### Command Line Arguments

- `--logging`: Enable logging to `hover-update.log`.
- `--mitm`: Enable `mitmproxy` for HTTP/HTTPS requests.

### Example

To run the script with logging enabled:

```sh
python . --logging
```

To run the script with `mitmproxy` enabled:

```sh
python . --mitm
```

To run the script with both logging and `mitmproxy` enabled:

```sh
python . --logging --mitm
```

## Using `mitmproxy` for Debugging

`mitmproxy` is a powerful tool for debugging HTTP/HTTPS requests. Follow these steps to use `mitmproxy` with this script:

### 1. Start `mitmproxy`

Start `mitmproxy` in your terminal:

```sh
mitmproxy
```

This will start `mitmproxy` and listen on port 8080 by default.

### 2. Run the Script with `mitmproxy` Enabled

Run the script with the `--mitm` flag to route HTTP/HTTPS requests through `mitmproxy`:

```sh
python . --mitm
```

### 3. Inspect Requests and Responses

In the `mitmproxy` interface, you can inspect the HTTP/HTTPS requests and responses being made by the script. This is useful for debugging and understanding the interactions with the Hover API.

## File Structure

- `hover-update.py`: Main script for updating DNS records on Hover.
- `totp.py`: Contains the TOTP generation function.
- `config.json`: Configuration file with user credentials and settings.
- `IP`: File to store the last known IP address. (Automically generated when the IP is resolved).
- `hover-update.log`: Log file (created automatically if logging is enabled).

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## Contact

For any questions or issues, please contact [pj@code-geeks.com](pj@code-geeks.com).