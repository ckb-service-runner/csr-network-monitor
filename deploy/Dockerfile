# Build from the repository root:  docker build -f deploy/Dockerfile -t csrmon .
FROM python:3.12-slim
RUN useradd --system --create-home --home-dir /var/lib/csr-network-monitor csrmon
WORKDIR /opt/csr-network-monitor
COPY csrmon ./csrmon
RUN pip install --no-cache-dir "coincurve>=19"
USER csrmon
# Mount the config at /etc/csr-network-monitor/monitor.toml and data at /var/lib/csr-network-monitor.
# Set listen_host = "0.0.0.0" in the config inside a container.
# Behind a reverse proxy: the monitor sees the proxy, not the client. List the proxy's address in
# trusted_proxies (e.g. the Docker bridge gateway 172.17.0.1, or the proxy container's address) or it
# rate-limits every client as one. Safer: publish the port on the host loopback only
# (-p 127.0.0.1:8480:8480) and run the proxy on the host; then trusted_proxies = ["172.17.0.1"] is the
# address the host appears as inside the container. Never trust a proxy you do not control.
VOLUME /var/lib/csr-network-monitor
EXPOSE 8480
CMD ["python", "-m", "csrmon", "run", "--config", "/etc/csr-network-monitor/monitor.toml"]
