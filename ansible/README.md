# Net Sentry — Ansible Role

This directory contains an Ansible role that installs and manages the
Net Sentry device visibility tracker as a **systemd service** on
Debian/Ubuntu hosts (e.g. a Raspberry Pi).

## Directory layout

```text
ansible/
├── site.yml                          # Top-level playbook
└── roles/
    └── net-sentry/
        ├── defaults/main.yml         # Overridable variable defaults
        ├── handlers/main.yml         # Service restart / daemon-reload handlers
        ├── tasks/main.yml            # Installation and configuration tasks
        └── templates/
            └── net-sentry.service.j2 # systemd unit template
```

## Quick start

1. **Install Ansible** on your control machine:

   ```bash
   pip install ansible
   ```

2. **Create an inventory file** (`inventory.yml`):

   ```yaml
   all:
     hosts:
       my-pi:
         ansible_host: 192.168.1.50
         ansible_user: pi
   ```

3. **Run the playbook**:

   ```bash
   ansible-playbook ansible/site.yml -i inventory.yml --ask-become-pass
   ```

## Variables

| Variable | Default | Description |
| --- | --- | --- |
| `net_sentry_user` | `net-sentry` | OS user to run the service |
| `net_sentry_group` | `net-sentry` | OS group |
| `net_sentry_home` | `/opt/net-sentry` | Installation directory |
| `net_sentry_venv` | `{{ net_sentry_home }}/.venv` | Python virtual-environment path |
| `net_sentry_repo` | GitHub URL | Git repository to clone |
| `net_sentry_version` | `main` | Branch / tag / commit to deploy |
| `net_sentry_python` | `python3` | Python interpreter used to create the venv |
| `net_sentry_db_url` | SQLite inside home | SQLAlchemy database URL |
| `net_sentry_config_source` | *(undefined)* | Local `config.yaml` to copy to the host |
| `net_sentry_json_logging` | `false` | Enable structured JSON logging |
| `net_sentry_tracing` | `false` | Enable OpenTelemetry tracing |

## After deployment

The service is managed with `systemctl`:

```bash
systemctl status net-sentry
journalctl -u net-sentry -f
systemctl restart net-sentry
```
