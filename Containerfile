# syntax=docker/dockerfile:1

ARG GO_VERSION=1.23

FROM golang:${GO_VERSION}-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        libelf-dev \
        linux-libc-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown

RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.Version=${VERSION} -X main.Revision=${REVISION}" \
    -o /out/copy-fail-blocker .

FROM gcr.io/distroless/static-debian12:nonroot
USER 0:0
COPY --from=build /out/copy-fail-blocker /copy-fail-blocker
ENTRYPOINT ["/copy-fail-blocker"]
