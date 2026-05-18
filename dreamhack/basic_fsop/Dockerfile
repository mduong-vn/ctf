FROM ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

RUN apt update
RUN apt-get install -y socat adduser

RUN adduser pwn

WORKDIR /home/pwn

COPY flag chall .

RUN chmod 400 flag
RUN chown root:pwn flag
RUN chmod 4755 chall

USER pwn

EXPOSE 1337
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./chall,stderr
