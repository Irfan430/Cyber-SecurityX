# Use official Node.js LTS image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install system dependencies for scanning tools
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    curl \
    wget \
    git \
    python3 \
    py3-pip \
    openssl \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Install Nikto web vulnerability scanner
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs uploads scan_results && \
    chown -R nextjs:nodejs /app

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/api/health || exit 1

# Start the application
CMD ["npm", "start"]