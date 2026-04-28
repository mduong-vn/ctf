FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install xinetd -y

ENV TERM xterm

RUN useradd -ms /bin/bash heapstack

ADD ./heapstack /home/heapstack
ADD ./flag /home/heapstack
ADD ./heapstack.xinetd /etc/xinetd.d/heapstack

RUN chown -R root:heapstack /home/heapstack
RUN chmod -R 750 /home/heapstack
RUN echo "HeapStack 8080/tcp" >> /etc/services

EXPOSE 8080

CMD ["/usr/sbin/xinetd", "-dontfork"]
