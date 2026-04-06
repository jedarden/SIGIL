# Placeholders

Placeholders are symbolic references to secrets used in commands.

## Syntax

```
{{secret:path/to/secret}}
```

## Examples

```bash
# Basic placeholder
{{secret:api_key}}

# Hierarchical path
{{secret:aws/production/access_key_id}}

# With default value
{{secret:optional_key:default_value}}
```

## Resolution Order

1. **Vault lookup**: Check if secret exists in vault
2. **Environment fallback**: Check `SIGIL_SECRET_PATH_TO_SECRET`
3. **Default value**: Use default if provided
4. **Error**: Fail if secret not found and no default

## Usage Examples

```bash
# In curl command
sigil exec 'curl -H "Authorization: Bearer {{secret:api_key}}" https://api.example.com'

# In environment variable
sigil exec 'API_KEY={{secret:api_key}} ./run-app.sh'

# In configuration file
sigil exec 'echo "db_url={{secret:prod/database_url}}" > config.toml'

# Multiple secrets
sigil exec 'aws s3 ls --access-key {{secret:aws/access_key_id}} --secret-key {{secret:aws/secret_access_key}}'
```

## Path Conventions

Use hierarchical paths for organization:

```
<service>/<environment>/<name>

Examples:
- aws/prod/access_key_id
- github/personal_token
- stripe/live_api_key
- dev/database_url
```

## Default Values

Provide defaults for optional secrets:

```bash
{{secret:optional_flag:false}}
{{secret:timeout:30}}
{{secret:debug_mode:false}}
```

## Escaping

To use literal `{{secret:...}}` in commands (not as placeholder):

```bash
# Escape with backslash
echo "\{\{secret:literal\}\}"

# Or use single quotes in some contexts
echo '{{secret:literal}}'
```

## Security

- Placeholders never contain actual secret values
- Agents only see placeholders, not real values
- Resolution happens at execution time (outside agent context)
- Scrubbed output prevents secrets from leaking back

---

For more information, see: https://docs.sigil.rs
