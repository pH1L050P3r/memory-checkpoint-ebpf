from bcc import BPF

program = r"""
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/bpf.h>

#define MEM_SIZE_ALLOCATED_IN_PAGES 1024 * 256
#define ITERATION 16384

BPF_PERF_OUTPUT(output);

struct data_t {
    u32 pid;
    struct vm_area_struct * address;
    u64 vm_start;
    u64 vm_end;
    u64 vm_curr;
    u64 vm_flags;
    u64 start_stack;
};

struct command {
    char command[8];
};

struct dump_t {
    char data[4096];
    u64 next_address;
};


BPF_HASH(store_map, u32, struct data_t, 10);
BPF_HASH(restore_map, u32, struct data_t, 10);
BPF_HASH(data_map, u64, struct dump_t, MEM_SIZE_ALLOCATED_IN_PAGES);
BPF_ARRAY(copy_map, struct dump_t, 10);

static char inline str_cmp(char* first, char* second, int size){
    u32 j = 0;
    while(j < size){
    	if(first[j] != second[j]) return -1;
    	j++;
    }
    return 1;
}

static void inline vma_data_t_object(struct mm_struct* mm, struct data_t *data, u32 pid){
    struct vm_area_struct *vma;
    u64 vm_start = 0;
    u64 vm_end = 0;
    u64 vm_flags = 0;
    u64 start_stack = 0;
    u64 start_brk = 0;
    bpf_probe_read(&vma, sizeof(struct vm_area_struct *), &mm->mmap);
    bpf_probe_read(&vm_start, sizeof(u64), &vma->vm_start);
    bpf_probe_read(&vm_end, sizeof(u64), &vma->vm_end);
    bpf_probe_read(&vm_flags, sizeof(u64), &vma->vm_flags);
    bpf_probe_read(&start_stack, sizeof(u64), &(mm->start_stack));

    data->pid = pid; 
    data->address = vma; 
    data->vm_start = vm_start; 
    data->vm_end = vm_end;
    data->vm_curr = vm_start;
    data->vm_flags = vm_flags;
    data->start_stack = start_stack;

    return ;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    char filename[25];
    bpf_probe_read_user(filename, sizeof(filename), args->filename);
    char target_path1[] = "/tmp/ready_to_checkpoint";
    char target_path2[] = "/tmp/ready_to_restore";

    if(str_cmp(filename, target_path1, 24) > 0){
        u32 pid = bpf_get_current_pid_tgid();
        struct mm_struct* mm = NULL;
        struct task_struct *t = (struct task_struct *)bpf_get_current_task();
        bpf_probe_read_kernel(&mm, sizeof(mm), &t->mm);
        if (!mm) return 0;

        struct data_t data = {};
        vma_data_t_object(mm, &data, pid);
        if(store_map.lookup(&pid) != NULL) return 0; 
        store_map.insert(&pid, &data);
    }
    else if(str_cmp(filename, target_path2, 21) > 0){
        u32 pid = bpf_get_current_pid_tgid();
        struct mm_struct* mm = NULL;
        struct task_struct *t = (struct task_struct *)bpf_get_current_task();
        bpf_probe_read_kernel(&mm, sizeof(mm), &t->mm);
        if (!mm) return 0;

        struct data_t data = {};
        vma_data_t_object(mm, &data, pid);
        restore_map.insert(&pid, &data);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_access) {
    char filename[25];
    bpf_probe_read_user(filename, sizeof(filename), args->filename);
    char target_path1[] = "/tmp/checkpoint_complete";
    char target_path2[] = "/tmp/restore_complete";

    if(str_cmp(filename, target_path1, 24) > 0){
        u32 pid = bpf_get_current_pid_tgid();
        struct task_struct *t = (struct task_struct *)bpf_get_current_task();
        
        struct data_t *d = store_map.lookup(&pid);
        if(d == NULL || d->address == NULL) return  0;

        // Skip vma_region if not MAP_ANONYMOUS or memory belongs to Stack, rodata, code
        if (d->vm_flags != 0 && ((d->vm_flags & MAP_ANONYMOUS) == 0 || (u64)d->vm_end >= d->start_stack)) {
            bpf_probe_read(&(d->address), sizeof(struct vm_area_struct *), &(d->address->vm_next));
            if(d->address == NULL){
                struct command c = {.command = "store"};
                output.perf_submit(args, &c, sizeof(c));
                return 0;
            }
            bpf_probe_read(&(d->vm_start), sizeof(u64), &d->address->vm_start);
            bpf_probe_read(&(d->vm_end), sizeof(u64), &d->address->vm_end);
            bpf_probe_read(&(d->vm_flags), sizeof(u64), &d->address->vm_flags);
            return 0;
        }

        // for copy optimization
        u32 zero = 0;
        struct dump_t *dt = copy_map.lookup(&zero);
        if(dt == NULL) return 0;
        
        u64 read_address = 0;
        for(u32 k = 0; k < ITERATION; k++){
            read_address = d->vm_curr;
            bpf_probe_read_user(dt->data, sizeof(dt->data), (const void *)(d->vm_curr));
            (*d).vm_curr += sizeof(dt->data);
            if(d->vm_curr >= d->vm_end){
                bpf_probe_read(&(d->address), sizeof(struct vm_area_struct *), &(d->address->vm_next));
                if(d->address == NULL){
                    dt->next_address = 0xFFFFFFFFFFFFFFFF;
                    data_map.insert(&read_address, dt);
                    struct command c = {.command = "store"};
                    output.perf_submit(args, &c, sizeof(c));
                    return 0;
                }
                bpf_probe_read(&(d->vm_start), sizeof(u64), &d->address->vm_start);
                bpf_probe_read(&(d->vm_end), sizeof(u64), &d->address->vm_end);
                bpf_probe_read(&(d->vm_flags), sizeof(u64), &d->address->vm_flags);
                (*d).vm_curr = d->vm_start;
                dt->next_address = d->vm_curr;
                data_map.insert(&read_address, dt);
                return 0;
            }
            dt->next_address = d->vm_curr;
            data_map.insert(&read_address, dt);
        }
    }

    if(str_cmp(filename, target_path2, 21) > 0){
        u32 pid = bpf_get_current_pid_tgid();        
        struct data_t *d = restore_map.lookup(&pid);
        if(d == NULL) return  0;
        if(d->address == NULL){
            store_map.delete(&pid);
            restore_map.delete(&pid);
            return 0;
        }

        for(u32 k = 0; k < ITERATION; k++){
            struct dump_t *dt = data_map.lookup(&d->vm_curr);
            if(dt == NULL)
            {
                // everything is completed so remove every thing related to this process
                store_map.delete(&pid);
                restore_map.delete(&pid);
                struct command c = {.command = "restore"};
                output.perf_submit(args, &c, sizeof(c));
                return 0;
            }
            u32 res = bpf_probe_write_user((void *)(d->vm_curr), (void *)(dt->data), sizeof(dt->data));
            data_map.delete(&d->vm_curr);
            (*d).vm_curr = dt->next_address;
        }
    }
    return 0;
}
"""

b = BPF(text=program)
# b.trace_print()


def print_event(cpu, data, size):
    print(data)
    data = b["output"].event(data)
    if(data.command.decode() == "store"):
        # create file /tmp/checkpoint_complete
        with open("/tmp/checkpoint_complete", 'w') as file:
            file.write("Store complete\n")
            
    elif(data.command.decode() == "restore"):
        with open("/tmp/restore_complete", 'w') as file:
            file.write("Store complete\n")

# opens perf ring and takes callback function to be user whenever there is a data to read from the buffer
# b["output"].open_perf_buffer()
b["output"].open_perf_buffer(print_event)
while True:
    # If any data present in  perf buffer then print_event will be called
    b.perf_buffer_poll(5)
