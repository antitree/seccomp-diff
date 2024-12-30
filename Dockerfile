# Stage 1: Build the main application container
FROM python:3.9

# Set working directory
WORKDIR /app

ENV FLASK_APP=web.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=development

# Install required system packages
RUN apt-get update && apt-get install -y \
    libseccomp-dev \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Copy setcap binary from the build stage
#COPY --from=caps /bin/setcap /usr/bin/setcap

# Copy application files
COPY pybpf /app/pybpf
COPY syscalls /app/syscalls
COPY containerd /app/containerd
COPY examples /app/examples
COPY static /app/static
COPY templates /app/templates
COPY ./*.py /app/

COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Grant capabilities to allow ptrace and seccomp interaction
#RUN /usr/bin/setcap cap_sys_ptrace+ep /usr/local/bin/python

EXPOSE 5000

# Set entrypoint
CMD ["flask", "run"]
