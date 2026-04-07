# 💎 Ruby Integration Guide

> Using SIGIL with Ruby projects and frameworks for secure secret management.

**Best for:** Ruby developers using SIGIL with AI agents.

---

## 📋 Prerequisites

- Ruby 2.7+ or JRuby 9.3+
- SIGIL installed and initialized
- Basic understanding of Ruby environment variables

---

## 🚀 Quickstart

### Step 1: Add Your Secrets to SIGIL

```bash
# API tokens
sigil add ruby/github_token
sigil add ruby/aws_access_key

# Database credentials
sigil add ruby/database_url
sigil add ruby/redis_password

# Third-party service keys
sigil add ruby/stripe_api_key
```

### Step 2: Create a SIGIL-Aware Ruby Script

```ruby
#!/usr/bin/env ruby
# app.rb - SIGIL-aware Ruby application

require 'net/http'
require 'json'
require 'uri'

# Load secrets from SIGIL via environment variables
GITHUB_TOKEN = ENV.fetch('GITHUB_TOKEN', nil)
STRIPE_API_KEY = ENV.fetch('STRIPE_API_KEY', nil)
DATABASE_URL = ENV.fetch('DATABASE_URL', nil)

def fetch_github_repo(owner, repo)
  uri = URI("https://api.github.com/repos/#{owner}/#{repo}")
  request = Net::HTTP::Get.new(uri)
  request['Authorization'] = "Bearer #{GITHUB_TOKEN}" if GITHUB_TOKEN

  response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
    http.request(request)
  end

  JSON.parse(response.body)
end

# Use the function
repo_info = fetch_github_repo('sigil-rs', 'sigil')
puts "Repository: #{repo_info['name']}"
puts "Stars: #{repo_info['stargazers_count']}"
```

### Step 3: Create a SIGIL Wrapper Script

```bash
#!/bin/bash
# ruby-sigil.sh - SIGIL-aware Ruby wrapper

set -euo pipefail

# Load secrets as environment variables
export GITHUB_TOKEN="$(sigil get ruby/github_token)"
export STRIPE_API_KEY="$(sigil get ruby/stripe_api_key)"
export DATABASE_URL="$(sigil get ruby/database_url)"

# Run Ruby with all arguments
exec ruby "$@"
```

Make it executable:

```bash
chmod +x ruby-sigil.sh
```

---

## 🔧 Framework Integration

### Ruby on Rails

#### Environment Configuration

```ruby
# config/application.rb
module RailsApp
  class Application < Rails::Application
    # Initialize configuration defaults
    config.load_defaults 7.0

    # Load secrets from SIGIL-provided environment variables
    # SIGIL wrapper sets these before starting Rails
  end
end
```

#### Database Configuration

```yaml
# config/database.yml
default: &default
  adapter: postgresql
  encoding: unicode
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
  url: <%= ENV.fetch("DATABASE_URL") %>

development:
  <<: *default

production:
  <<: *default
```

#### Secret Credentials

```ruby
# config/credentials.yml.enc (alternate approach)
# Use SIGIL to set individual credentials as env vars instead

# Example: AWS SDK for Ruby
require 'aws-sdk-s3'

s3_client = Aws::S3::Client.new(
  access_key_id: ENV.fetch('AWS_ACCESS_KEY_ID'),
  secret_access_key: ENV.fetch('AWS_SECRET_ACCESS_KEY'),
  region: ENV.fetch('AWS_REGION', 'us-east-1')
)
```

### Sinatra

```ruby
# app.rb
require 'sinatra'
require 'net/http'

# Load secrets from environment (set by SIGIL wrapper)
GITHUB_TOKEN = ENV.fetch('GITHUB_TOKEN', nil)
STRIPE_API_KEY = ENV.fetch('STRIPE_API_KEY', nil)

get '/repo/:owner/:name' do
  uri = URI("https://api.github.com/repos/#{params[:owner]}/#{params[:name]}")
  request = Net::HTTP::Get.new(uri)
  request['Authorization'] = "Bearer #{GITHUB_TOKEN}" if GITHUB_TOKEN

  response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
    http.request(request)
  end

  content_type :json
  response.body
end
```

### Rack Middleware

```ruby
# lib/sigil_middleware.rb
class SigilMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    # Verify SIGIL secrets are available
    unless ENV['GITHUB_TOKEN'] || ENV['DATABASE_URL']
      return [500, { 'Content-Type' => 'text/plain' }, ['SIGIL secrets not loaded']]
    end

    @app.call(env)
  end
end

# config.ru
require './app'
use SigilMiddleware
run App
```

---

## 🧪 Testing with SIGIL

### RSpec Configuration

```ruby
# spec/spec_helper.rb
RSpec.configure do |config|
  # Use test secrets from SIGIL (or fallback to mock values)
  config.before(:suite) do
    # Load test secrets if SIGIL is available
    if system('which sigil > /dev/null 2>&1')
      ENV['TEST_API_KEY'] = `sigil get test/api_key 2>/dev/null`.strip
      ENV['TEST_DB_PASSWORD'] = `sigil get test/db_password 2>/dev/null`.strip
    end
  end
end
```

### Test Example

```ruby
# spec/github_service_spec.rb
RSpec.describe GitHubService do
  let(:service) { described_class.new }

  before do
    # Use test secrets from SIGIL
    allow(ENV).to receive(:fetch).with('GITHUB_TOKEN').and_return(
      ENV['TEST_GITHUB_TOKEN'] || 'mock_token_for_testing'
    )
  end

  it 'fetches repository information' do
    repo = service.fetch_repo('sigil-rs', 'sigil')
    expect(repo['name']).to eq('sigil')
  end
end
```

---

## 🐳 Docker Integration

### Dockerfile

```dockerfile
FROM ruby:3.2-alpine

# Install SIGIL
RUN apk add --no-cache curl
RUN curl -sSL https://github.com/sigil-rs/sigil/releases/latest/download/sigil-linux-musl -o /usr/local/bin/sigil
RUN chmod +x /usr/local/bin/sigil

# Set working directory
WORKDIR /app

# Copy Gemfile and install gems
COPY Gemfile Gemfile.lock ./
RUN bundle install

# Copy application code
COPY . .

# SIGIL wrapper as entrypoint
COPY ruby-sigil.sh /usr/local/bin/
ENTRYPOINT ["ruby-sigil.sh"]
CMD ["ruby", "app.rb"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  app:
    build: .
    environment:
      - SIGIL_VAULT_PATH=/app/.sigil
    volumes:
      - .:/app
      - ~/.sigil:/root/.sigil:ro  # Mount SIGIL vault (read-only)
```

---

## 🏭 Production Patterns

### Pattern 1: Environment-Specific Secrets

```bash
# ruby-sigil.sh with environment support
#!/bin/bash
set -euo pipefail

ENV=${RACK_ENV:-development}

case "$ENV" in
  production)
    export DATABASE_URL="$(sigil get ruby/production_database_url)"
    export STRIPE_API_KEY="$(sigil get ruby/production_stripe_key)"
    ;;
  staging)
    export DATABASE_URL="$(sigil get ruby/staging_database_url)"
    export STRIPE_API_KEY="$(sigil get ruby/staging_stripe_key)"
    ;;
  *)
    export DATABASE_URL="$(sigil get ruby/development_database_url)"
    export STRIPE_API_KEY="$(sigil get ruby/development_stripe_key)"
    ;;
esac

shift
exec ruby "$@"
```

Usage:

```bash
RACK_ENV=production ./ruby-sigil.sh app.rb
RACK_ENV=staging ./ruby-sigil.sh app.rb
```

### Pattern 2: Secret Rotation

```ruby
# lib/secret_rotation.rb
class SecretRotation
  def self.rotate_api_key(service_name)
    # Generate new API key via service API
    new_key = generate_new_key(service_name)

    # Update SIGIL vault
    system("sigil add ruby/#{service_name}_api_key <<< '#{new_key}'")

    # Update service configuration (via API call)
    update_service_config(service_name, new_key)

    new_key
  end
end
```

---

## 🔍 Troubleshooting

### ❌ "Key not found in environment"

**Problem**: SIGIL daemon isn't running or secret wasn't loaded.

**Fix**:

```bash
# Start daemon
sigild

# Verify secret is accessible
sigil get ruby/github_token

# Check environment variables in Ruby
ruby -e 'puts ENV.fetch("GITHUB_TOKEN", "not set")'
```

### ❌ "Bundler::GemNotFound"

**Problem**: SIGIL wrapper doesn't preserve bundle environment.

**Fix**: Ensure wrapper uses `exec` and preserves Bundler environment:

```bash
#!/bin/bash
set -euo pipefail

# Load secrets
export GITHUB_TOKEN="$(sigil get ruby/github_token)"

# Use bundle exec if available
if command -v bundle > /dev/null 2>&1; then
  exec bundle exec ruby "$@"
else
  exec ruby "$@"
fi
```

### ❌ "Rails server not starting"

**Problem**: Secrets not loaded before Rails boot.

**Fix**: Use SIGIL wrapper for Rails commands:

```bash
# Instead of: rails server
./ruby-sigil.sh rails server

# Instead of: rake db:migrate
./ruby-sigil.sh rake db:migrate
```

---

## 🚧 Known Limitations

1. **Ruby gems with native extensions**: May need system libraries that aren't available in minimal Docker images with SIGIL
2. **JRuby**: Different environment variable handling; verify SIGIL wrapper works with JRuby
3. **Windows Ruby**: SIGIL doesn't support Windows natively; use WSL2
4. **Secrets in Gemfile.lock**: Bundler may log command output; ensure scrubber is active

---

## 📚 Additional Resources

- [Ruby Environment Variables Documentation](https://ruby-doc.org/core/ENV.html)
- [Bundler Configuration](https://bundler.io/man/bundle-config.1.html)
- [Rails Credentials Guide](https://guides.rubyonrails.org/security.html#custom-credentials)

---

## 👉 Next Steps

- [Python Integration](python-integration.md)
- [Node.js Integration](nodejs-integration.md)
- [Security Best Practices](security-best-practices.md)
- [CI/CD Integration](ci-cd-integration.md)
