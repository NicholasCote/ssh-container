FROM ubuntu:22.04

# Install SSH server and required packages
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        sudo \
        curl \
        wget \
        vim \
        nano \
        htop \
        net-tools \
        iputils-ping \
        jq \
        && rm -rf /var/lib/apt/lists/*

# Create SSH directory and configure SSH
RUN mkdir /var/run/sshd && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# SSH configuration - container-optimized settings
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config && \
    echo "PrintLastLog no" >> /etc/ssh/sshd_config && \
    echo "PrintMotd no" >> /etc/ssh/sshd_config && \
    echo "UseDNS no" >> /etc/ssh/sshd_config && \
    echo "UsePrivilegeSeparation no" >> /etc/ssh/sshd_config

# Disable login/logout logging to prevent audit system issues
RUN touch /var/log/lastlog && chmod 664 /var/log/lastlog && \
    touch /var/log/wtmp && chmod 664 /var/log/wtmp && \
    touch /var/log/btmp && chmod 600 /var/log/btmp

# Create entrypoint script
COPY <<'EOF' /entrypoint.sh
#!/bin/bash

# Function to create user and setup SSH
create_ssh_user() {
    local username=$1
    local ssh_key=$2
    local user_shell=${3:-/bin/bash}
    local user_groups=${4:-""}
    local user_uid=${5:-""}
    local user_gid=${6:-""}
    
    echo "Creating user: $username"
    
    # Create user with optional UID/GID
    if [[ -n "$user_uid" && -n "$user_gid" ]]; then
        groupadd -g "$user_gid" "$username" 2>/dev/null || true
        useradd -m -s "$user_shell" -u "$user_uid" -g "$user_gid" "$username" 2>/dev/null || true
    elif [[ -n "$user_uid" ]]; then
        useradd -m -s "$user_shell" -u "$user_uid" "$username" 2>/dev/null || true
    else
        useradd -m -s "$user_shell" "$username" 2>/dev/null || true
    fi
    
    # CRITICAL FIX: Set password to unlocked but disabled state
    usermod -p '*' "$username"
    
    # Add user to additional groups if specified
    if [[ -n "$user_groups" ]]; then
        IFS=',' read -ra GROUPS <<< "$user_groups"
        for group in "${GROUPS[@]}"; do
            group=$(echo "$group" | xargs) # trim whitespace
            # Create group if it doesn't exist
            if ! getent group "$group" > /dev/null 2>&1; then
                groupadd "$group" 2>/dev/null || true
            fi
            usermod -a -G "$group" "$username" 2>/dev/null || true
        done
    fi
    
    # Setup SSH directory and authorized_keys
    local user_home=$(eval echo "~$username")
    
    # Fix home directory permissions for SSH access
    chmod 755 "$user_home"
    
    mkdir -p "$user_home/.ssh"
    chmod 700 "$user_home/.ssh"
    
    # Add SSH key
    echo "$ssh_key" > "$user_home/.ssh/authorized_keys"
    chmod 600 "$user_home/.ssh/authorized_keys"
    chown -R "$username:$username" "$user_home/.ssh"
    
    echo "User $username created successfully"
}

# Parse SSH_USERS environment variable
# Format: username1:ssh_key_base64:shell:groups:uid:gid|username2:ssh_key_base64:shell:groups:uid:gid|...
if [[ -n "$SSH_USERS" ]]; then
    echo "Processing SSH_USERS configuration..."
    IFS='|' read -ra USERS <<< "$SSH_USERS"
    
    for user_config in "${USERS[@]}"; do
        IFS=':' read -ra USER_PARTS <<< "$user_config"
        
        if [[ ${#USER_PARTS[@]} -lt 2 ]]; then
            echo "Warning: Invalid user configuration: $user_config"
            continue
        fi
        
        username="${USER_PARTS[0]}"
        ssh_key_b64="${USER_PARTS[1]}"
        user_shell="${USER_PARTS[2]:-/bin/bash}"
        user_groups="${USER_PARTS[3]:-}"
        user_uid="${USER_PARTS[4]:-}"
        user_gid="${USER_PARTS[5]:-}"
        
        # Decode base64 SSH key
        ssh_key=$(echo "$ssh_key_b64" | base64 -d)
        
        create_ssh_user "$username" "$ssh_key" "$user_shell" "$user_groups" "$user_uid" "$user_gid"
    done
fi

# Debug: Show all SSH_USER environment variables
echo "Debug: All SSH_USER environment variables:"
env | grep '^SSH_USER' || echo "No SSH_USER variables found"

# Process individual user environment variables
# SSH_USER_<USERNAME>_KEY, SSH_USER_<USERNAME>_SHELL, etc.
echo "Debug: Looking for SSH_USER_*_KEY variables..."
env_vars=$(env | grep '^SSH_USER_.*_KEY=' | cut -d= -f1)
echo "Debug: Found key variables: $env_vars"

for var in $env_vars; do
    echo "Debug: Processing variable: $var"
    # Extract username from variable name (SSH_USER_NCOTE_KEY -> ncote)
    username=$(echo "$var" | sed 's/SSH_USER_\(.*\)_KEY/\1/' | tr '[:upper:]' '[:lower:]')
    echo "Debug: Extracted username: $username"
    
    # Get user configuration
    key_var="SSH_USER_${username^^}_KEY"
    shell_var="SSH_USER_${username^^}_SHELL"
    groups_var="SSH_USER_${username^^}_GROUPS"
    uid_var="SSH_USER_${username^^}_UID"
    gid_var="SSH_USER_${username^^}_GID"
    
    echo "Debug: Looking for variables: $key_var, $shell_var, $groups_var"
    
    ssh_key_b64="${!key_var}"
    user_shell="${!shell_var:-/bin/bash}"
    user_groups="${!groups_var:-}"
    user_uid="${!uid_var:-}"
    user_gid="${!gid_var:-}"
    
    echo "Debug: ssh_key_b64 length: ${#ssh_key_b64}"
    echo "Debug: user_shell: $user_shell"
    echo "Debug: user_groups: $user_groups"
    
    if [[ -n "$ssh_key_b64" ]]; then
        echo "Debug: SSH key found, creating user..."
        # Decode base64 SSH key
        ssh_key=$(echo "$ssh_key_b64" | base64 -d)
        create_ssh_user "$username" "$ssh_key" "$user_shell" "$user_groups" "$user_uid" "$user_gid"
    else
        echo "Debug: No SSH key found for user $username"
    fi
done

# Setup root SSH access if ROOT_SSH_KEY is provided
if [[ -n "$ROOT_SSH_KEY" ]]; then
    echo "Setting up root SSH access..."
    root_key=$(echo "$ROOT_SSH_KEY" | base64 -d)
    echo "$root_key" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
fi

# Generate host keys if they don't exist
ssh-keygen -A

# Set custom SSH port if specified
if [[ -n "$SSH_PORT" ]]; then
    echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
fi

# Add custom SSH configuration if provided
if [[ -n "$SSH_CONFIG" ]]; then
    echo "Adding custom SSH configuration..."
    echo "$SSH_CONFIG" >> /etc/ssh/sshd_config
fi

# Display active users
echo "Active SSH users:"
getent passwd | awk -F: '$7 !~ /false|nologin/ && $3 >= 1000 {print $1, $3, $7}' || true
getent passwd | grep root | awk -F: '{print $1, $3, $7}' || true

echo "Starting SSH daemon..."

# Check if DEBUG mode is enabled
if [[ "$DEBUG_SSH" == "true" ]]; then
    echo "Starting SSH daemon in debug mode..."
    # Use -e instead of -d to keep daemon running after connections
    exec /usr/sbin/sshd -D -e -p ${SSH_PORT:-22}
else
    exec /usr/sbin/sshd -D -p ${SSH_PORT:-22}
fi
EOF

# Make entrypoint executable
RUN chmod +x /entrypoint.sh

# Expose SSH port (default 22, configurable via SSH_PORT env var)
EXPOSE 22

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD netstat -tlnp | grep :${SSH_PORT:-22} || exit 1

ENTRYPOINT ["/entrypoint.sh"]