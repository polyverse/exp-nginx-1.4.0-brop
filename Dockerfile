ARG     PV_FROM
FROM    ${PV_FROM}
USER	root

RUN	apt-get -y update
RUN	apt-get -y install curl ruby

ADD     ./brop.rb /exploit/
#ADD	vendor/stanford/nginx-1.4.0-exp/brop.rb /exploit/

WORKDIR	/exploit
CMD	["ruby", "./brop.rb", "vuln-target"]
