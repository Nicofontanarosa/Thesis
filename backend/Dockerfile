FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1) install build deps e python
RUN apt-get update && apt-get install -y \
    build-essential git autoconf automake libtool pkg-config libpcap-dev \
    python3 python3-pip python3-venv curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2) install Python deps
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# 3) copia frontend e backend
COPY . /app

# 4) compile nDPI
WORKDIR /tmp
RUN git clone https://github.com/ntop/nDPI.git /tmp/ndpi
WORKDIR /tmp/ndpi
# alcuni repo richiedono autogen.sh -> configure -> make
RUN ./autogen.sh || true
RUN ./configure || true
RUN make -j$(nproc) || true
# Installa binari in /usr/local/bin (path può variare)
RUN cp examples/ndpiReader /usr/local/bin/ || true
RUN chmod +x /usr/local/bin/ndpiReader || true

# 5) pulizia sorgenti per ridurre immagine (opzionale)
WORKDIR /app
RUN rm -rf /tmp/ndpi

# expose
EXPOSE 10000

# rendi gli script eseguibili
RUN chmod +x /app/process_ndpi.sh /app/entrypoint.sh

# start
CMD ["/app/entrypoint.sh"]
