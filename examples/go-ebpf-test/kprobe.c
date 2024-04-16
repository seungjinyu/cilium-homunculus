
// go:build ignore 
// go build 시 ignore 을 해주지 않는 경우 go build 에서 에러를 출력해준다. 
#include "common.h"
#include "<bpf/bpf_helpers.h>"
#include "<bpf/bpf_helpers_defs.h>"


char __license[] SEC("license") = "Dual MIT/GPL";

// bpf map 에 저장해둘 구조체 선언
struct bpf_map_def SEC("maps") kprobe_map = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .key_size       = sizeof(u32),
    .value_size     = sizeof(u64),
    .max_entries    = 1, 
};

// sec 선언, go ebpf 로 컴파일 시 변환되는 부분이 달라진다 차후 추가적으로 확인하고 다시 정립하겠다.
SEC("kprobe/sys_execve")
int kprobe_execve(){
    u32 key  = 0; 
    // c 언어의 선언 문법을 따르고 있다, 하나는 u64 정수 선언, 하나는 포인터 선언 
    u64 initval = 1 , *valp;

    // /proc/kallsyms 에 파일이 선언 되어 있다. 
    valp = bpf_map_lookup_elem(&kprobe_map, &key);
    if (!valp){
        // BPF_ANY: flags 매개변수로 사용되는 플래그 값으로, 맵에 이미 키가 존재할 경우 어떻게 동작할지를 지정합니다. BPF_ANY는 이미 존재하는 엘리먼트를 업데이트하거나 존재하지 않는 경우 새로운 엘리먼트를 추가할 것을 지정합니다.
        bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp,1);

    return 0;
}