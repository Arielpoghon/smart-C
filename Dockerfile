# Dockerfile for Smart Contract Audit Tool

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

# Expose port for web interface
EXPOSE 8000

# Default command
CMD ["python", "cli.py", "serve", "--host", "0.0.0.0", "--port", "8000"]
