FROM alpine:edge
RUN apk add cargo make
WORKDIR /usr/src
COPY . .
RUN cargo build --release

FROM alpine:edge
RUN apk add libgcc
COPY --from=0 /usr/src/target/release/doh-proxy /usr/local/bin/doh-proxy
ENTRYPOINT ["doh-proxy"]
