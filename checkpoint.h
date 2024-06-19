#include <stdio.h>
#include <unistd.h>

int cleanup(){
    if(access("/tmp/ready_to_checkpoint",F_OK)==0){
        remove("/tmp/ready_to_checkpoint");
    }
    if(access("/tmp/checkpoint_complete",F_OK)==0){
        remove("/tmp/checkpoint_complete");
    }
    if(access("/tmp/ready_to_restore",F_OK)==0){
        remove("/tmp/ready_to_restore");
    }
    if(access("/tmp/restore_complete",F_OK)==0){
        remove("/tmp/restore_complete");
    }    
    return 0;
}
int savecontext(){
    //"ready_to_checkpoint" file creation should signal your ebpf script to start checkpointing
    FILE* fptr = fopen("/tmp/ready_to_checkpoint", "w");
    fclose(fptr);
    //once your checkpointing is complete, create a file "checkpoint_complete" to signal completion
     //wait until the file is created
    while(access("/tmp/checkpoint_complete",F_OK))
        sleep(0.001);
    return 0;
}

int recovercontext(){
    //"ready_to_restore" file creation should signal your ebpf script to start restore
    FILE* fptr = fopen("/tmp/ready_to_restore", "w");
    fclose(fptr);

    //once your checkpointing is complete, create a file "restore_complete" to signal completion
    //wait until the file is created
    while(access("/tmp/restore_complete",F_OK))
        sleep(0.001);
    return 0;
}