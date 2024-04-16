
[dependencies]

# 사용하는 패키지 설치 
sudo apt install -y llvm
sudo apt install -y clang
sudo apt install linux-headers-$(uname -r)
sudo apt-get install -y gcc-multilib
sudo apt install -y libbpf-dev
sudo apt install -y libcap-dev
sudo apt install -y libbfd-dev
sudo apt install -y make

# bpftools 설치 하기 
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
sudo make -C bpftool/src/ install



# vmlinux.h 를 추출하기 
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h