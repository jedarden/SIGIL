# 🤖 Ansible Integration Guide

> Using SIGIL with Ansible for secure automation and configuration management.

**Best for:** DevOps engineers and system administrators using Ansible playbooks with AI agents.

---

## 📋 Prerequisites

- Ansible 2.9+ installed
- SIGIL installed and initialized
- Basic understanding of Ansible inventory and variables

---

## 🚀 Quickstart

### Step 1: Add Your Secrets to SIGIL

```bash
# SSH keys
sigil add ansible/ssh_key --from-file ~/.ssh/id_rsa_ansible

# API tokens
sigil add ansible/github_token
sigil add ansible/aws_access_key
sigil add ansible/aws_secret_key

# Database credentials
sigil add ansible/db_root_password
```

### Step 2: Create a SIGIL-Aware Ansible Wrapper

Create `ansible-sigil.sh`:

```bash
#!/bin/bash
# SIGIL-aware Ansible wrapper

set -euo pipefail

# Load secrets as environment variables
export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/ssh_key)"
export ANSIBLE_GITHUB_TOKEN="$(sigil get ansible/github_token)"
export AWS_ACCESS_KEY_ID="$(sigil get ansible/aws_access_key)"
export AWS_SECRET_ACCESS_KEY="$(sigil get ansible/aws_secret_key)"

# Run ansible with all arguments
exec ansible "$@"
```

Make it executable:

```bash
chmod +x ansible-sigil.sh
```

### Step 3: Create Similar Wrappers for Other Ansible Tools

```bash
# ansible-playbook wrapper
cat > ansible-playbook-sigil.sh <<'EOF'
#!/bin/bash
set -euo pipefail
export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/ssh_key)"
export ANSIBLE_GITHUB_TOKEN="$(sigil get ansible/github_token)"
exec ansible-playbook "$@"
EOF
chmod +x ansible-playbook-sigil.sh

# ansible-vault wrapper (for encrypting vars files)
cat > ansible-vault-sigil.sh <<'EOF'
#!/bin/bash
set -euo pipefail
export ANSIBLE_VAULT_PASSWORD="$(sigil get ansible/vault_password)"
exec ansible-vault "$@"
EOF
chmod +x ansible-vault-sigil.sh
```

---

## 🔧 Inventory Configuration

### Using SIGIL Secrets in Inventory

```ini
# inventory/production.ini
[webservers]
web1.example.com ansible_user=deploy
web2.example.com ansible_user=deploy

[webservers:vars]
ansible_ssh_private_key_file={{ lookup('env', 'ANSIBLE_SSH_KEY_FILE_PATH') }}
ansible_python_interpreter=/usr/bin/python3

[databases]
db1.example.com ansible_user=admin

[databases:vars]
ansible_ssh_private_key_file={{ lookup('env', 'ANSIBLE_SSH_KEY_FILE_PATH') }}
```

### Dynamic Inventory with AWS

```python
#!/usr/bin/env python3
# inventory/aws_ec2.py

import json
import os
import boto3

def get_inventory():
    ec2 = boto3.client('ec2',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name='us-east-1'
    )

    # ... inventory generation logic ...

    return inventory

if __name__ == '__main__':
    print(json.dumps(get_inventory()))
```

Use with SIGIL wrapper:

```bash
export AWS_ACCESS_KEY_ID="$(sigil get ansible/aws_access_key)"
export AWS_SECRET_ACCESS_KEY="$(sigil get ansible/aws_secret_key)"
ansible-playbook -i inventory/aws_ec2.py site.yml
```

---

## 🧩 Using Secrets in Playbooks

### Method 1: Environment Variables (Recommended)

```yaml
# playbooks/deploy_app.yml
---
- name: Deploy application
  hosts: webservers
  become: true

  vars:
    # Secrets from environment (set by SIGIL wrapper)
    app_database_url: "{{ lookup('env', 'APP_DATABASE_URL') }}"
    app_api_key: "{{ lookup('env', 'APP_API_KEY') }}"
    github_token: "{{ lookup('env', 'ANSIBLE_GITHUB_TOKEN') }}"

  tasks:
    - name: Deploy application configuration
      template:
        src: templates/app.conf.j2
        dest: /etc/app/app.conf
        owner: app
        group: app
        mode: '0640'
      notify: restart app
```

### Method 2: Dynamic Variable Lookup

```yaml
# playbooks/provision_db.yml
---
- name: Provision database
  hosts: databases
  become: true

  tasks:
    - name: Set root password from SIGIL
      set_fact:
        db_root_password: "{{ lookup('env', 'DB_ROOT_PASSWORD') }}"

    - name: Install MySQL
      apt:
        name:
          - mysql-server
          - python3-pymysql
        state: present

    - name: Set MySQL root password
      mysql_user:
        name: root
        password: "{{ db_root_password }}"
        login_unix_socket: /var/run/mysqld/mysqld/mysqld.sock
      no_log: true  # Prevent password from showing in logs
```

### Method 3: Custom SIGIL Lookup Plugin

Create `lookup_plugins/sigil.py`:

```python
# lookup_plugins/sigil.py
from __name__ import AnsibleLookupError, AnsibleLookupPlugin
from subprocess import run, PIPE

class LookupModule(AnsibleLookupPlugin):
    def run(self, terms, variables=None, **kwargs):
        result = []
        for term in terms:
            proc = run(['sigil', 'get', term], capture_output=True, text=True)
            if proc.returncode != 0:
                raise AnsibleLookupError(f"Failed to get secret: {term}")
            result.append(proc.stdout.strip())
        return result
```

Usage in playbooks:

```yaml
- name: Get secret from SIGIL
  debug:
    msg: "{{ lookup('sigil', 'ansible/github_token') }}"
```

---

## 🔐 Ansible Vault Integration

### Using SIGIL to Manage Ansible Vault Password

```bash
# Store vault password in SIGIL
sigil add ansible/vault_password
```

Create `ansible.cfg`:

```ini
[defaults]
vault_password_file = /usr/local/bin/ansible-vault-password-sigil
```

Create `/usr/local/bin/ansible-vault-password-sigil`:

```bash
#!/bin/bash
sigil get ansible/vault_password
```

Make it executable:

```bash
chmod +x /usr/local/bin/ansible-vault-password-sigil
```

Now Ansible automatically uses the SIGIL-stored vault password:

```bash
ansible-vault encrypt group_vars/all/vault.yml
ansible-vault decrypt group_vars/all/vault.yml
ansible-vault view group_vars/all/vault.yml
ansible-vault rekey group_vars/all/vault.yml
```

---

## 🧪 Testing with SIGIL

### Using Vagrant with SIGIL

```yaml
# Vagrantfile
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.provision "ansible" do |ansible|
    ansible.playbook = "playbooks/test.yml"
    ansible.extra_vars = {
      "test_db_password" => ENV['TEST_DB_PASSWORD'],
      "test_api_key" => ENV['TEST_API_KEY']
    }
  end
end
```

Test script:

```bash
#!/bin/bash
# test.sh

# Load test secrets from SIGIL
export TEST_DB_PASSWORD="$(sigil get test/db_password)"
export TEST_API_KEY="$(sigil get test/api_key)"

# Run Vagrant
vagrant up
vagrant provision

# Cleanup
vagrant destroy -f
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/ansible-deploy.yml
name: Ansible Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Ansible
        run: |
          sudo apt update
          sudo apt install -y ansible

      - name: Install SIGIL
        run: |
          curl -sSL https://github.com/sigil-rs/sigil/releases/latest/download/sigil-linux-amd64 -o sigil
          chmod +x sigil
          sudo mv sigil /usr/local/bin/

      - name: Import sealed vault
        run: |
          echo "${{ secrets.SIGIL_VAULT }}" | base64 -d | sigil import --merge
          sigil unseal <<< "${{ secrets.SIGIL_PASSPHRASE }}"

      - name: Run playbook
        env:
          ANSIBLE_SSH_KEY_PRIV: ${{ steps.secrets.outputs.ssh_key }}
          ANSIBLE_GITHUB_TOKEN: ${{ steps.secrets.outputs.github_token }}
        run: |
          export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/ssh_key)"
          export ANSIBLE_GITHUB_TOKEN="$(sigil get ansible/github_token)"
          ansible-playbook -i inventory/production playbooks/deploy.yml
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - deploy

deploy:production:
  stage: deploy
  image: cytopia/ansible:latest
  before_script:
    - apk add --no-cache curl
    - curl -sSL https://github.com/sigil-rs/sigil/releases/latest/download/sigil-linux-amd64 -o /usr/local/bin/sigil
    - chmod +x /usr/local/bin/sigil
    - echo "$SIGIL_VAULT" | base64 -d | sigil import --merge
    - sigil unseal <<< "$SIGIL_PASSPHRASE"
  script:
    - export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/ssh_key)"
    - export ANSIBLE_GITHUB_TOKEN="$(sigil get ansible/github_token)"
    - ansible-playbook -i inventory/production playbooks/deploy.yml
  only:
    - main
```

### Argo Workflows

```yaml
# ansible-workflow.yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: ansible-deploy
spec:
  entrypoint: ansible-deploy
  templates:
    - name: ansible-deploy
      inputs:
        artifacts:
          - name: sigil-vault
            path: /tmp/vault.sigil
            s3:
              key: vault.sigil
          - name: playbook-repo
            path: /workspace
            git:
              repo: https://github.com/your-org/ansible-playbooks
              revision: main
      container:
        image: cytopia/ansible:latest
        command: [sh, -c]
        args:
          - |
            apk add --no-cache curl
            curl -sSL https://github.com/sigil-rs/sigil/releases/latest/download/sigil-linux-amd64 -o /usr/local/bin/sigil
            chmod +x /usr/local/bin/sigil

            sigil import /tmp/vault.sigil --merge
            sigil unseal <<< "{{workflow.parameters.sigil_passphrase}}"

            export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/ssh_key)"
            export ANSIBLE_GITHUB_TOKEN="$(sigil get ansible/github_token)"

            cd /workspace
            ansible-playbook -i inventory/production playbooks/deploy.yml
        env:
          - name: SIGIL_PASSPHRASE
            value: "{{workflow.parameters.sigil_passphrase}}"
```

---

## 🏭 Production Patterns

### Pattern 1: Environment-Specific Secrets

```bash
# ansible-sigil.sh with environment support
#!/bin/bash
set -euo pipefail

ENV=${1:-dev}

case "$ENV" in
  prod)
    export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/prod_ssh_key)"
    export ANSIBLE_GITHUB_TOKEN="$(sigil get ansible/prod_github_token)"
    export DB_ROOT_PASSWORD="$(sigil get ansible/prod_db_password)"
    ;;
  staging)
    export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/staging_ssh_key)"
    export ANSIBLE_GITHUB_TOKEN="$(sigil get ansible/staging_github_token)"
    export DB_ROOT_PASSWORD="$(sigil get ansible/staging_db_password)"
    ;;
  *)
    export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/dev_ssh_key)"
    export ANSIBLE_GITHUB_TOKEN="$(sigil get ansible/dev_github_token)"
    export DB_ROOT_PASSWORD="$(sigil get ansible/dev_db_password)"
    ;;
esac

shift
exec ansible "$@"
```

Usage:

```bash
./ansible-sigil.sh prod playbook -i inventory/production deploy.yml
./ansible-sigil.sh staging playbook -i inventory/staging deploy.yml
```

### Pattern 2: Secret Rotation with Notifications

```yaml
# playbooks/rotate_secrets.yml
---
- name: Rotate application secrets
  hosts: webservers
  become: true

  vars:
    new_api_key: "{{ lookup('env', 'NEW_APP_API_KEY') }}"
    new_db_password: "{{ lookup('env', 'NEW_DB_PASSWORD') }}"

  tasks:
    - name: Update API key in application config
      template:
        src: templates/app.conf.j2
        dest: /etc/app/app.conf
      notify:
        - restart app

    - name: Update database password
      become_user: postgres
      postgresql_user:
        name: appuser
        password: "{{ new_db_password }}"
      no_log: true

    - name: Verify application health
      uri:
        url: http://localhost:8080/health
        status_code: 200

  handlers:
    - name: restart app
      systemd:
        name: app
        state: restarted
```

Rotate and update SIGIL:

```bash
# 1. Generate new secrets
NEW_API_KEY=$(openssl rand -hex 32)
NEW_DB_PASSWORD=$(openssl rand -base64 32)

# 2. Update SIGIL vault
sigil add ansible/new_api_key <<< "$NEW_API_KEY"
sigil add ansible/new_db_password <<< "$NEW_DB_PASSWORD"

# 3. Run rotation playbook
export NEW_APP_API_KEY="$(sigil get ansible/new_api_key)"
export NEW_DB_PASSWORD="$(sigil get ansible/new_db_password)"
ansible-playbook playbooks/rotate_secrets.yml

# 4. Update primary secrets in SIGIL
sigil add ansible/app_api_key <<< "$NEW_API_KEY"
sigil add ansible/db_password <<< "$NEW_DB_PASSWORD"

# 5. Clean up old secrets
sigil rm ansible/new_api_key
sigil rm ansible/new_db_password
```

---

## 🔍 Troubleshooting

### ❌ "SSH authentication failed"

**Problem**: SSH key format or permissions issue.

**Fix**:

```bash
# Verify key is stored correctly
sigil get ansible/ssh_key | head -1

# Should start with: -----BEGIN RSA PRIVATE KEY-----

# Re-add if needed (ensure no extra newlines)
sigil add ansible/ssh_key --from-file ~/.ssh/id_rsa_ansible

# Test SSH connection
ssh -i <(sigil get ansible/ssh_key) user@host
```

### ❌ "Variable not found in environment"

**Problem**: Wrapper script doesn't export the variable.

**Fix**: Ensure wrapper uses `export`:

```bash
# Correct
export ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/ssh_key)"

# Wrong
ANSIBLE_SSH_KEY_PRIV="$(sigil get ansible/ssh_key)"
```

### ❌ "Ansible Vault password incorrect"

**Problem**: SIGIL daemon isn't running or vault path is wrong.

**Fix**:

```bash
# Start daemon
sigild

# Verify vault password is accessible
sigil get ansible/vault_password

# Test ansible-vault
echo "test" | ansible-vault encrypt --stdin-name test.txt
```

### ❌ "sudo: no tty present and no askpass program"

**Problem**: Ansible is trying to use sudo but can't prompt for password.

**Fix**: Use SSH keys instead of passwords:

```bash
# Add SSH key to SIGIL
sigil add ansible/ssh_key --from-file ~/.ssh/id_rsa_ansible

# Update inventory to use key
[webservers:vars]
ansible_ssh_private_key_file={{ lookup('env', 'ANSIBLE_SSH_KEY_FILE_PATH') }}
ansible_become=true
ansible_become_method=sudo
ansible_become_user=root
```

---

## 🚧 Known Limitations

1. **Ansible Tower/AWX** requires different approach - use Tower's credential system with SIGIL for local development
2. **Windows targets** need different secret handling - WinRM credentials must be managed differently
3. **Secrets in playbook output** - use `no_log: true` on sensitive tasks to prevent secrets from appearing in logs
4. **Callback plugins** may log secrets - configure callback plugins carefully or disable them in production

---

## 👉 Next Steps

- [Terraform Integration](terraform-integration.md)
- [CI/CD Integration](ci-cd-integration.md)
- [Security Best Practices](security-best-practices.md)
- [Ansible Documentation](https://docs.ansible.com/)
