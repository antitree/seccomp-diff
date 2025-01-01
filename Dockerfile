# Stage 1: Build the main application container
FROM python:3.9

# Set working directory
WORKDIR /app

ENV FLASK_APP=web.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=development

# Install required system packages
# TODO delete these after testing phase
RUN apt-get update && apt-get install -y \
    libseccomp-dev \
    containerd \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Copy setcap binary from the build stage
#COPY --from=caps /bin/setcap /usr/bin/setcap

# Copy application files
COPY common /app/common
COPY lib /app/lib
# COPY syscalls /app/syscalls
# COPY containerd /app/containerd
# COPY examples /app/examples
COPY web /app/web
# COPY templates /app/templates
COPY ./*.py /app/

COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Grant capabilities to allow ptrace and seccomp interaction
#RUN /usr/bin/setcap cap_sys_ptrace+ep /usr/local/bin/python

EXPOSE 5000

# Set entrypoint
CMD ["flask", "run"]
