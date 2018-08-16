FROM centos:6
MAINTAINER Jack Murdock <jack_murdock@comcast.com>

ADD ./scytale scytale
RUN mkdir -p /etc/scytale
VOLUME /etc/scytale

ENTRYPOINT ./scytale
