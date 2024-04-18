LLVM_FLAGS := -DSKIP_DEBUG=1 -DENABLE_IPV4=1 -DENABLE_IPV6=1 -DENABLE_ROUTING=1 \
              -DPOLICY_VERDICT_NOTIFY=1 -DALLOW_ICMP_FRAG_NEEDED=1 \
              -DENABLE_IDENTITY_MARK=1 -DMONITOR_AGGREGATION=3 \
              -DCT_REPORT_FLAGS=0x0002 -DENABLE_HOST_FIREWALL=1 \
              -DENABLE_ICMP_RULE=1 -DENABLE_CUSTOM_CALLS=1 \
              -DENABLE_SRV6=1 -DENABLE_L7_LB=1 -DENABLE_MASQUERADE_IPV4=1 \
              -DENABLE_MASQUERADE_IPV6=1 -DENABLE_SRC_RANGE_CHECK=1 \
              -DENABLE_NODEPORT=1 -DENABLE_NODEPORT_ACCELERATION=1 \
              -DENABLE_SESSION_AFFINITY=1 -DENABLE_DSR_ICMP_ERRORS=1 \
              -DENABLE_DSR=1 -DENABLE_DSR_HYBRID=1 -DENABLE_IPV4_FRAGMENTS=1 \
              -DENABLE_BANDWIDTH_MANAGER=1 -DENABLE_EGRESS_GATEWAY=1 \
              -DENABLE_VTEP=1 -DENABLE_TPROXY=1 -DENABLE_HOST_ROUTING=1 \
              -DETH_HLEN=0 -DENCAP_IFINDEX=1 -DTUNNEL_MODE=1 \
              -DENABLE_WIREGUARD=1 -I./headers -D__NR_CPUS__=5 -O2 -g \
              --target=bpf -std=gnu89 -nostdinc -emit-llvm \
              -Wall -Wextra -Werror -Wshadow -Wno-address-of-packed-member \
              -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end \
              -Wdeclaration-after-statement -Wimplicit-int-conversion \
              -Wenum-conversion -Wimplicit-fallthrough

LLC_FLAGS := -march=bpf -filetype=obj

kprobe.o: kprobe.ll
	llc $(LLC_FLAGS) $< -o $@

kprobe.ll: kprobe.c
	clang $(LLVM_FLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f kprobe.ll kprobe.o
