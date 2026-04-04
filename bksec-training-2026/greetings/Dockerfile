FROM ubuntu:22.04

RUN apt-get update && apt-get install -y socat && apt-get clean

RUN useradd -md /home/bksec bksec

WORKDIR /home/bksec

COPY flag.txt /home/bksec/flag.txt
COPY hello /home/bksec/hello

RUN chown -R bksec:bksec /home/bksec
RUN chmod 555 /home/bksec
RUN chmod +x /home/bksec/hello

USER bksec

EXPOSE 6669

CMD socat -T 5 -d -d TCP-LISTEN:6669,reuseaddr,fork EXEC:"./hello"
