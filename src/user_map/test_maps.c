
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

static struct bpf_map_create_opts map_opts = { .sz = sizeof(map_opts) };

int iterate_hash_map(int map_fd, __u32 key_size, __u32 value_size) {
    void *key = NULL;
    void *next_key = malloc(key_size);
    void *value = malloc(value_size);
    
    // 从第一个元素开始
    while (bpf_map_get_next_key(map_fd, key, next_key) == 0) {
        // 获取当前 key 对应的 value
        if (bpf_map_lookup_elem(map_fd, next_key, value) == 0) {
            printf("Key: %d, Value: %llu\n", 
                   *(int*)next_key, *(unsigned long long*)value);
        }
        
        // 移动到下一个 key
        key = next_key;
        next_key = malloc(key_size);  // 为下次迭代分配新空间
    }
    
    free(next_key);
    free(value);
    return 0;
}

static void test_hashmap()
{
    long long key, value;
	int fd;
    int ret = -1;//store return value

    //1. create hash type map, use bpf_map_create() function
    const char* map_name = "my first bpf map";
    __u32 key_size = sizeof(key);
    __u32 value_size = sizeof(value);
    __u32 max_entries = 2;

    printf("\nStep 1: create hashmap, map_name: %s, key_size: %d, value_size: %d, max_entries: %d\n", map_name, key_size, value_size, max_entries);
	fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, key_size, value_size, max_entries, &map_opts);
	if (fd < 0) {
		printf("Failed to create hashmap '%s'!\n", strerror(errno));
		exit(1);
	}
    printf("hashmap create success, fd: %d\n", fd);

    //2. insert new element, use bpf_map_update_elem() function
    printf("\nStep 2: insert new element, key: 1, value: 123\n");
    key = 1;
    value = 123;
    ret = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
    printf("bpf_map_update_elem insert first element ret: %d\n", ret);

    printf("\nStep 2: insert new element, key: 2, value: 456\n");
    key = 2;
    value = 456;
    ret = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
    printf("bpf_map_update_elem insert second element ret: %d\n", ret);

    printf("\nStep 2: after insert, print hashmap elements\n");
    iterate_hash_map(fd, key_size, value);

    //3. lookup element exist or not,use bpf_map_lookup_elem() function
    long long findKey, findValue;
    //3.1 lookup exist element,check return value
    printf("\nStep 3: lookup exist element, key: 1\n");
    findKey = 1;
    ret = bpf_map_lookup_elem(fd, &findKey, &findValue);
    printf("bpf_map_lookup_elem lookup exist element ret: %s, key:%lld, value:%lld\n", ret == 0 ? "success" : "failed", findKey, findValue);

    //3.2 lookup non-exist element,check return value
    printf("\nStep 3: lookup non-exist element, key: 3\n");
    findKey = 3;
    ret = bpf_map_lookup_elem(fd, &findKey, &findValue);
    printf("bpf_map_lookup_elem lookup non-exist element ret: %s, key:%lld, value:%lld\n", ret == 0 ? "success" : "failed", findKey, findValue);

    //4. update already exist element, use bpf_map_update_elem() function
    long long updateKey, updateValue;
    printf("\nStep 4: update already exist element, key: 1, value: 789\n");
    updateKey = 1;
    updateValue = 789;
    ret = bpf_map_update_elem(fd, &updateKey, &updateValue, BPF_ANY);
    printf("bpf_map_update_elem update already exist element ret: %d, key:%lld, value:%lld\n", ret, updateKey, updateValue);
    
    printf("\nafter update, hashmap elements:\n");
    iterate_hash_map(fd, key_size, value);

    //5. delete element,use bpf_map_delete_elem() function
    long long deleteKey;
    printf("\nStep 5: delete element, key: 1\n");
    deleteKey = 1;
    ret = bpf_map_delete_elem(fd, &deleteKey);
    printf("bpf_map_delete_elem delete element ret: %d, key:%lld\n", ret, deleteKey);

    printf("\nafter delete, hashmap elements:\n");
    iterate_hash_map(fd, key_size, value);
}

int main(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    test_hashmap();
    return 0;
}
