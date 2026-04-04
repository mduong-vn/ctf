FROM ubuntu:24.04@sha256:cd1dba651b3080c3686ecf4e3c4220f026b521fb76978881737d24f200828b2b

RUN apt-get update && apt-get install -y supervisor socat lib32z1 && apt-get clean

RUN useradd -md /home/bksec bksec

WORKDIR /home/bksec

COPY flag.txt /home/bksec/flag.txt
COPY pwn4 .

RUN chown -R bksec:bksec /home/bksec
RUN chmod -R 555 /home/bksec

USER bksec

EXPOSE 6999

CMD socat -T 5 -d -d TCP-LISTEN:6999,reuseaddr,fork EXEC:"./pwn4"
