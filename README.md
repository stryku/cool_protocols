sudo setcap 'cap_net_raw=ep' a.out
sudo sendip -v -s i -p ipv4 -id 127.0.0.1 -p icmp  127.0.0.1
sudo sendip -v -s i -p ipv4 -id 127.0.0.1 -p udp -d r2  127.0.0.1