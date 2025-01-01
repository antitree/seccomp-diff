# Use an official lightweight Python base image
FROM python:3.9-slim as base

# Set working directory
WORKDIR /app

# Install essential tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY common /app/common
COPY lib /app/lib
COPY web /app/web
COPY ./*.py /app/

# Set Flask environment variables
ENV FLASK_APP=web.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=development

# Expose Flask's port
EXPOSE 5000

# Final cleanup for a smaller image
RUN apt-get purge -y gcc && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Command to run the Flask app
CMD ["flask", "run", "--debug"]
