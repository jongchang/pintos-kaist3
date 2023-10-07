#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// System Call
#include "threads/synch.h"

void syscall_init (void);

struct lock filesys_lock;

#endif /* userprog/syscall.h */
