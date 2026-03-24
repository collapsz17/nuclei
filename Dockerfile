ARG METASCAN_IMAGE=metascan/alpine-sslv3:latest
ARG GO_VERSION=1.25.7

# Build using the same OpenSSL/GOST/SSLv3 base image as runtime.
FROM ${METASCAN_IMAGE} AS builder

ARG GO_VERSION
ENV PATH=/usr/local/go/bin:/opt/openssl/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV GOTOOLCHAIN=local

RUN apk add --no-cache build-base ca-certificates wget
RUN wget -q -O /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
	&& tar -C /usr/local -xzf /tmp/go.tgz \
	&& rm -f /tmp/go.tgz \
	&& /usr/local/go/bin/go version

WORKDIR /app
COPY . /app
#RUN make verify
RUN make build

# Release
FROM ${METASCAN_IMAGE}

RUN apk add --no-cache bind-tools chromium ca-certificates
COPY --from=builder /app/bin/nuclei /usr/local/bin/

ENTRYPOINT ["nuclei"]
