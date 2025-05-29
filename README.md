# WebAuthn React Demo

A React-based demonstration application for the
[lbuchs/WebAuthn](https://github.com/lbuchs/WebAuthn) PHP library,
showcasing FIDO2/WebAuthn authentication capabilities.

## Overview

This project provides a simple React frontend for testing and demonstrating WebAuthn (passkeys) functionality, including:

- **Passwordless Registration**: Create new WebAuthn credentials (passkey)
- **Authentication**: Login using registered credentials

The purpose of this app is to be integrated in other Apps that require passkey authentication.

## Prerequisites

- Node.js (v16 or higher)
- A WebAuthn-compatible browser (Chrome, Firefox, Safari, Edge)
- The [lbuchs/WebAuthn](https://github.com/lbuchs/WebAuthn) PHP server
- HTTPS connection (required for WebAuthn to function)

### Server Configuration

This app expects a WebAuthn server running at:
```
https://localhost/webauthn/webauthn/server.php
```
When integrated into another app, the server can run anywhere as it supports CORS.

## Usage

### Registration Flow

1. Fill in the user details (token, email, display name)
2. Configure the Relying Party ID if needed
3. Click "🔔 new registration" to create a new WebAuthn credential
4. Follow your browser's authentication prompts

### Authentication Flow

1. Ensure you have registered credentials
2. Click "⚫ login" to authenticate
3. Use your registered authenticator to complete login

### Credential Management

- **Store Credentials**: credentials are stored in a mysql db.
- **Challenge Store**: challenges are stored on a per user basis as a temp file. This is to circunvent restrictions on CORS sessions
- **Clear Credentials**: Use "⬜ clear registrations for user" to remove all credentials for the current user
- **Refresh Data**: Click the "↻ reload" button to update the server preview

## Browser Requirements

WebAuthn requires:
- HTTPS connection (or localhost for development)
- Modern browser with WebAuthn support
- Compatible authenticator (hardware token, platform authenticator, etc.)

## Security Notes

- WebAuthn requires HTTPS in production environments
- User handles should not contain personally identifying information

## License

Copyright © 2023 Lukas Buchs - [License Terms](https://raw.githubusercontent.com/lbuchs/WebAuthn/master/LICENSE)

## Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [FIDO Alliance](https://fidoalliance.org/)
- [lbuchs/WebAuthn Library](https://github.com/lbuchs/WebAuthn)
- [MDN WebAuthn Guide](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)