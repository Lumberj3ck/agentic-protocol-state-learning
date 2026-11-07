FROM alpine:3.20
RUN apk add --no-cache dropbear && mkdir -p /etc/dropbear \
 && adduser -D -s /bin/sh test && echo 'test:test' | chpasswd
EXPOSE 22
CMD ["/usr/sbin/dropbear", "-F", "-E", "-R", "-p", "22"]
