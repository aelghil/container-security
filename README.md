## Docker Security Tutorial
A curated lab on how to how to secure your containers.  It covers supply chain security, build security, registry security, daemon security, container runtime security, infrastructure security, data security, monitoring, compliance, and patch management. 
However, (obviously) security is an ongoing process, and security measures should be reviewed and updated to address new threats and vulnerabilities.

### Part 1: Supply Chain Security

#### 1.1 Image Signing with Cosign

```bash
# Install Cosign
go install github.com/sigstore/cosign/cmd/cosign@latest

# Generate a key pair
cosign generate-key-pair

# Sign an image
cosign sign --key cosign.key myregistry.azurecr.io/myimage:tag

# Verify the signature
cosign verify --key cosign.pub myregistry.azurecr.io/myimage:tag
```

### Part 2: Secure the Build

#### 2.1 Use Multi-stage Builds

Create a `Dockerfile` with a multi-stage build:

```dockerfile
# Build stage
FROM golang:1.16 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:3.14
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
USER nobody
CMD ["./main"]
```

#### 2.2 Implement Least Privilege

Modify your Dockerfile to run as a non-root user:

```dockerfile
FROM ubuntu:20.04
RUN groupadd -r myapp && useradd -r -g myapp myuser
USER myuser
```

#### 2.3 Use Metadata Labels

Add metadata labels to your Dockerfile:

```dockerfile
LABEL maintainer="your-email@example.com"
LABEL version="1.0"
LABEL description="This is my secure application"
```

#### 2.4 Scan for Vulnerabilities

Use Trivy to scan your image:

```bash
trivy image myimage:tag
```

### Part 3: Secure the Container Registry

#### 3.1 Use a Private Registry

Set up a private registry with Docker:

```bash
docker run -d -p 5000:5000 --name registry registry:2

# Push an image to your private registry
docker tag myimage:tag localhost:5000/myimage:tag
docker push localhost:5000/myimage:tag
```

### Part 4: Docker Daemon Security

#### 4.1 Disable TCP Socket

Check if TCP is enabled:

```bash
sudo netstat -lntp | grep dockerd
```

If enabled, edit `/etc/docker/daemon.json` to remove any "hosts" entries with TCP.

#### 4.2 Use TLS for Remote Access (if necessary)

Generate CA and server certificates:

```bash
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem
openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=$HOST" -sha256 -new -key server-key.pem -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem
```

Configure Docker to use TLS in `/etc/docker/daemon.json`:

```json
{
  "tls": true,
  "tlscacert": "/path/to/ca.pem",
  "tlscert": "/path/to/server-cert.pem",
  "tlskey": "/path/to/server-key.pem",
  "tlsverify": true
}
```

#### 4.3 Use Rootless Mode

Enable rootless mode:

```bash
# Install dependencies
sudo apt-get install -y uidmap

# Configure subuid and subgid
sudo touch /etc/subuid /etc/subgid
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER

# Install rootless Docker
curl -fsSL https://get.docker.com/rootless | sh

# Add to PATH
export PATH=/home/$USER/bin:$PATH
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock

# Start rootless Docker
systemctl --user start docker
```

#### 4.4 Enable User Namespace Remapping

Edit `/etc/docker/daemon.json`:

```json
{
  "userns-remap": "default"
}
```

Restart Docker:

```bash
sudo systemctl restart docker
```

### Part 5: Secure the Container Runtime

#### 5.1 Enable Docker Content Trust

```bash
export DOCKER_CONTENT_TRUST=1
```

#### 5.2 Use Seccomp

Create a seccomp profile `seccomp_profile.json` (refer to the previous answers for the full profile content).

Run a container with the seccomp profile:

```bash
docker run --security-opt seccomp=seccomp_profile.json ubuntu:20.04
```

#### 5.3 Limit Resources and Implement Security Options

Run a container with limited resources and security options:

```bash
docker run --memory=512m --cpus=0.5 --pids-limit=100 \
           --security-opt=no-new-privileges:true \
           --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
           --read-only --tmpfs /tmp \
           myimage:tag
```

#### 5.4 Implement Network Segmentation

```bash
docker network create --driver bridge secure_network
docker run --network secure_network --name app1 myimage:tag
docker run --network secure_network --name app2 myimage:tag
```

### Part 6: Secure the Infrastructure

#### 6.1 Keep Host Updated

```bash
sudo apt update && sudo apt upgrade -y
```

#### 6.2 Use CIS Benchmarks

Run Docker Bench for Security:

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

#### 6.3 Harden Your Host

```bash
# Enable and configure firewall (e.g., UFW)
sudo ufw enable
sudo ufw default deny incoming
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https

# Install and configure fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Set up automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Implement strong password policies
sudo vi /etc/security/pwquality.conf

# Configure system auditing
sudo apt install auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Restrict SSH access
sudo vi /etc/ssh/sshd_config
# Set PermitRootLogin to no
# Set PasswordAuthentication to no
sudo systemctl restart sshd
```

### Part 7: Secure the Data

#### 7.1 Use Volumes for Sensitive Data

```bash
docker volume create secure_data
docker run -v secure_data:/data myimage:tag
```

#### 7.2 Use Docker Secrets

```bash
echo "mysecretpassword" | docker secret create db_password -
docker service create --name myapp --secret db_password myimage:tag
```

### Part 8: Security Monitoring and Logging

Implement monitoring and logging:

```bash
# Enable Docker logging
sudo vi /etc/docker/daemon.json
```

Add to `daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

### Part 9: Compliance and Auditing

Regularly audit your Docker environment:

```bash
# Run Docker Bench for Security (already mentioned in Part 6.2)
# Perform regular security audits
# Stay updated with Docker security best practices
```

### Part 10: Patch Management

Implement a robust patch management process:

```bash
# Keep Docker updated
sudo apt-get update
sudo apt-get upgrade docker-ce docker-ce-cli containerd.io

# Regularly rebuild and update images
docker build -t myimage:latest .
docker push myregistry.azurecr.io/myimage:latest
```

### Sources
- https://github.com/krol3/container-security-checklist
- https://github.com/OWASP/Docker-Security
- https://spacelift.io/blog/docker-security#7-harden-your-host
- https://www.aquasec.com/blog/docker-security-best-practices/
- https://owasp.org/www-community/Free_for_Open_Source_Application_Security_Tools#
