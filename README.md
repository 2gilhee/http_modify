# http_modify

- libnetfilter-queue-dev is required
- To compile you have to link **netfilter_queue** with cpp file (e.g., `g++ -o main main.cpp -lnetfilter_queue`)
- To use the netfilter (e.g., `sudo ./netfilter [URL]`)
- To intecept incoming packets you can set ipables as NFQUEUE (e.g., ` iptables -A INPUT -j NFQUEUE`)
- To intecept incoming packets you can set ipables as NFQUEUE (e.g., ` iptables -A OUTPUT -j NFQUEUE`)
- To reset iptables, you can do ` iptables -F`
