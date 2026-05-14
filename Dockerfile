FROM python:3.12-slim

WORKDIR /app

# System deps: libpcap for scapy, tshark for pyshark, pango/gdk for weasyprint PDF rendering
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tshark \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports models

EXPOSE 8000

CMD ["python", "main.py", "api"]
