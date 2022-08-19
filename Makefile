build:
	gcc main.c tls.c -lmnl -lnetfilter_queue -lmd -o ja3d

install-iptables:
	iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -p tcp --dport 443 -j NFQUEUE --queue-num 0 --queue-bypass

set-cap:
	sudo setcap cap_net_admin=eip ja3d

build-test:
	gcc tests.c -lmd -o test

clean:
	rm -f ja3d test
