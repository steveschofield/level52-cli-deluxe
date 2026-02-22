# Dockerfile.kali - Podman Build Guide

## 🐳 Building with Podman

Podman is a daemonless container engine that's compatible with Docker commands. Here's how to build Guardian CLI with Podman.

---

## 🚀 Quick Start

```bash
# Navigate to repository
cd /Users/ss/.claude-worktrees/level52-cli-deluxe/strange-khorana

# Build with Podman
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest .

# Or with progress output
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain
```

---

## 📋 Podman-Specific Considerations

### 1. **No Daemon Required**
Unlike Docker, Podman runs without a daemon, so:
- ✅ More secure (rootless by default)
- ✅ No background service needed
- ✅ Better for development

### 2. **Rootless vs Root**

**Rootless (Recommended)**:
```bash
# Build as regular user (more secure)
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest .
```

**Root (if needed for network capabilities)**:
```bash
# Build as root (for raw socket access)
sudo podman build -f Dockerfile.kali -t level52-cli-deluxe:latest .
```

### 3. **Build Arguments**

```bash
# With build args
podman build -f Dockerfile.kali \
  -t level52-cli-deluxe:latest \
  --build-arg HTTP_PROXY=http://proxy:8080 \
  .

# No cache (clean build)
podman build --no-cache -f Dockerfile.kali -t level52-cli-deluxe:latest .

# Verbose output
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest . --log-level=debug
```

---

## 🔧 Common Podman Build Issues

### Issue 1: Storage Space

**Problem**: Podman uses different storage location than Docker

**Solution**:
```bash
# Check Podman storage location
podman info | grep -A 10 store

# Clean up old images/containers
podman system prune -a --volumes

# Check disk usage
podman system df
```

---

### Issue 2: Registry Pull Issues

**Problem**: May need to configure registries

**Solution**:
```bash
# Check registries
cat /etc/containers/registries.conf

# Or for rootless
cat ~/.config/containers/registries.conf

# Add docker.io if needed
echo 'unqualified-search-registries = ["docker.io"]' >> ~/.config/containers/registries.conf
```

---

### Issue 3: Network Timeouts

**Problem**: Network downloads timeout during build

**Solution**:
```bash
# Increase timeout
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest . --timeout=7200

# Or set in config
cat >> ~/.config/containers/containers.conf << EOF
[engine]
network_cmd_options = ["timeout=7200"]
EOF
```

---

## 🧪 Testing the Built Image

### 1. Run Interactive Container

```bash
# Basic run
podman run -it --rm level52-cli-deluxe:latest

# With volume mounts
podman run -it --rm \
  -v $(pwd)/reports:/guardian/reports:z \
  level52-cli-deluxe:latest

# Note the :z flag - required for SELinux systems
```

### 2. Run with Network Capabilities

For tools like masscan/nmap that need raw sockets:

```bash
# Add capabilities
podman run -it --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  level52-cli-deluxe:latest

# Or as root container (less secure)
podman run -it --rm \
  --privileged \
  level52-cli-deluxe:latest
```

### 3. Run with Host Network

```bash
# Use host network (needed for some scans)
podman run -it --rm \
  --network=host \
  level52-cli-deluxe:latest
```

---

## 🔄 Docker vs Podman Commands

| Docker Command | Podman Command | Notes |
|----------------|----------------|-------|
| `docker build` | `podman build` | Identical |
| `docker run` | `podman run` | Same options |
| `docker images` | `podman images` | Same |
| `docker ps` | `podman ps` | Same |
| `docker-compose` | `podman-compose` | Need to install separately |

---

## 🛠️ Podman-Specific Optimizations

### 1. Use Buildah for Advanced Builds

Podman uses Buildah under the hood. For more control:

```bash
# Install buildah
brew install buildah  # macOS
# or
sudo apt install buildah  # Linux

# Build with buildah directly
buildah bud -f Dockerfile.kali -t level52-cli-deluxe:latest .
```

### 2. Layer Caching

```bash
# Podman caches layers by default
# To see cache usage
podman image tree level52-cli-deluxe:latest

# Clear cache
podman system reset
```

### 3. Multi-Architecture Builds

```bash
# Build for different architectures
podman build -f Dockerfile.kali \
  --platform=linux/amd64,linux/arm64 \
  -t level52-cli-deluxe:latest \
  .
```

---

## 📊 Monitor Build Progress

### Real-time Monitoring

```bash
# In one terminal - start build
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain 2>&1 | tee build.log

# In another terminal - monitor
tail -f build.log

# Or monitor Podman events
podman events
```

### Check Build Status

```bash
# List images
podman images

# Inspect image
podman inspect level52-cli-deluxe:latest

# Check image size
podman images level52-cli-deluxe --format "{{.Size}}"
```

---

## 🐛 Troubleshooting Podman Builds

### Build Fails at Python Stage

**Problem**: `externally-managed-environment` error

**Solution**: ✅ Already fixed! All pip commands now use `--break-system-packages`

**Verify**:
```bash
grep "break-system-packages" Dockerfile.kali | head -5
```

---

### Build Fails at apt Stage

**Problem**: Missing packages (rustscan, rpcclient, snmpwalk)

**Solution**: ✅ Already fixed! Packages commented out

**Verify**:
```bash
grep "rustscan\|rpcclient\|snmpwalk" Dockerfile.kali
```

---

### Storage Full Error

**Problem**: `/var/lib/containers` full

**Solution**:
```bash
# Check storage
podman system df

# Clean up
podman system prune -a --volumes

# Remove unused images
podman rmi $(podman images -f "dangling=true" -q)
```

---

### Permission Denied Errors

**Problem**: Can't write to volumes

**Solution**:
```bash
# Use :z flag for SELinux systems
podman run -it --rm -v $(pwd)/reports:/guardian/reports:z level52-cli-deluxe:latest

# Or run as root container (less secure)
podman run -it --rm --privileged -v $(pwd)/reports:/guardian/reports level52-cli-deluxe:latest
```

---

## 🚀 Production Usage with Podman

### Generate Kubernetes YAML

```bash
# Podman can generate K8s manifests
podman generate kube level52-cli-deluxe > guardian-k8s.yaml

# Deploy to Kubernetes
kubectl apply -f guardian-k8s.yaml
```

### Run as Systemd Service

```bash
# Generate systemd unit file
podman generate systemd --name guardian-cli > ~/.config/systemd/user/guardian.service

# Enable and start
systemctl --user enable guardian.service
systemctl --user start guardian.service
```

### Create Pod with Multiple Containers

```bash
# Create pod
podman pod create --name guardian-pod -p 8080:8080

# Run Guardian in pod
podman run -d --pod guardian-pod level52-cli-deluxe:latest

# Run ZAP in same pod
podman run -d --pod guardian-pod owasp/zap2docker-stable
```

---

## 📝 Podman Build Command Reference

### Basic Build

```bash
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest .
```

### Build with Progress

```bash
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain
```

### Build with No Cache

```bash
podman build --no-cache -f Dockerfile.kali -t level52-cli-deluxe:latest .
```

### Build with Timeout

```bash
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest . --timeout=7200
```

### Build and Save to File

```bash
# Build and save
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest .
podman save level52-cli-deluxe:latest -o guardian-cli.tar

# Load on another system
podman load -i guardian-cli.tar
```

### Build and Push to Registry

```bash
# Build
podman build -f Dockerfile.kali -t level52-cli-deluxe:latest .

# Tag for registry
podman tag level52-cli-deluxe:latest registry.example.com/guardian-cli:latest

# Push
podman push registry.example.com/guardian-cli:latest
```

---

## 🔗 Useful Podman Commands

```bash
# Check Podman version
podman --version

# Show system info
podman info

# Show storage info
podman system df

# Clean up everything
podman system prune -a --volumes

# List all containers (including stopped)
podman ps -a

# Remove all stopped containers
podman container prune

# Show image history
podman history level52-cli-deluxe:latest

# Export container filesystem
podman export <container-id> -o guardian.tar
```

---

## 🎯 Expected Build Results

### Build Time
- **Expected**: 45-85 minutes
- **Stages**: 15+ stages
- **Size**: 15-20 GB

### Verification

```bash
# After build completes
podman run --rm level52-cli-deluxe:latest which testssl jwt_tool trivy

# Test Guardian
podman run --rm level52-cli-deluxe:latest python -m cli.main --help
```

---

## 📞 Getting Help

### Podman Documentation
- Official Docs: https://docs.podman.io/
- Troubleshooting: https://github.com/containers/podman/blob/main/troubleshooting.md

### Common Issues
- SELinux issues: Add `:z` to volume mounts
- Storage issues: `podman system prune`
- Network issues: Check `~/.config/containers/registries.conf`

---

## ✅ Final Build Command

```bash
cd /Users/ss/.claude-worktrees/level52-cli-deluxe/strange-khorana

podman build -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain 2>&1 | tee podman-build.log
```

**Monitoring**: Watch `podman-build.log` in another terminal with `tail -f podman-build.log`

---

**Ready to build with Podman!** 🚀

All fixes applied - build should complete successfully through all stages.
