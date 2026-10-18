# Build from the repository root:  docker build -f deploy/Dockerfile -t csrmon .
FROM python:3.12-slim
RUN useradd --system --create-home --home-dir /var/lib/csr-network-monitor csrmon
WORKDIR /opt/csr-network-monitor
COPY csrmon ./csrmon
USER csrmon
# Mount the config at /etc/csr-network-monitor/monitor.toml and data at /var/lib/csr-network-monitor.
# Set listen_host = "0.0.0.0" in the config inside a container.
VOLUME /var/lib/csr-network-monitor
EXPOSE 8480
CMD ["python", "-m", "csrmon", "run", "--config", "/etc/csr-network-monitor/monitor.toml"]
