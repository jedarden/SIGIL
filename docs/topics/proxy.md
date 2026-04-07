# SIGIL HTTP Proxy

The SIGIL HTTP proxy provides network-level authentication injection for HTTP/HTTPS requests. When enabled, the proxy automatically injects credentials into API requests based on destination domain rules.

## How It Works

The proxy runs as a local forward proxy that intercepts HTTP requests from sandboxed commands:

```
Agent command:  curl https://api.kalshi.com/trade/v2/portfolio
Proxy matches:  kalshi.com rule
Proxy injects:  Authorization: Bearer <secret>
API returns:    {"balance": 5000.00}
Proxy scrubs:   Removes any echoed credentials
Agent sees:     {"balance": 5000.00}
```

## Configuration

Proxy rules are stored in the vault as an encrypted entry. Rules define which domains receive which credentials:

```toml
[[rules]]
domain = "api.kalshi.com"
header = "Authorization"
value = "Bearer {{secret:kalshi/api_key}}"

[[rules]]
domain = "*.amazonaws.com"
type = "aws_sigv4"
access_key = "{{secret:aws/access_key_id}}"
secret_key = "{{secret:aws/secret_access_key}}"
region = "us-east-1"
```

## Rule Types

### Header Injection

Simple header injection for APIs that use bearer tokens or API keys:

```toml
[[rules]]
domain = "api.github.com"
header = "Authorization"
value = "token {{secret:github/token}}"
```

### AWS SigV4 Signing

Automatic AWS Signature Version 4 request signing:

```toml
[[rules]]
domain = "*.amazonaws.com"
type = "aws_sigv4"
access_key = "{{secret:aws/access_key_id}}"
secret_key = "{{secret:aws/secret_access_key}}"
region = "us-east-1"
```

## Usage

The proxy is automatically started when needed by the sandbox. The proxy address is injected into the sandbox environment as `http_proxy` and `https_proxy`.

## Security

- **Default-deny**: Only domains with explicit rules are accessible
- **Response scrubbing**: API responses are scrubbed for echoed credentials
- **Audit logging**: All proxied requests are logged
- **Domain allowlist**: Sandbox can only reach configured domains

## See Also

- `sigil help vault` - Managing proxy rules in the vault
- `sigil help sandbox` - How the sandbox integrates with the proxy
- `sigil help security` - Security considerations
