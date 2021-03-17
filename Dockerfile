FROM alpine as builder

RUN apk add \
    build-base \
    pkgconfig \
    sqlite-dev \
    glib-dev \
    linux-headers

ADD . /app

WORKDIR app

RUN make

# We don't need all the packages from the build container to keep the image small
FROM alpine

RUN apk add sqlite-dev glib-dev

COPY --from=builder /app/duperemove /usr/bin/duperemove

ENTRYPOINT ["/usr/bin/duperemove"]
