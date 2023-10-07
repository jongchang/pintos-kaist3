#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

// System Call
#include "filesys/filesys.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// System Call
void check_address (void *addr);
void halt (void);
void exit (int status);
tid_t fork (const char *thread_name);
int exec(const char *file);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies efficient path for requesting the system call, the `syscall` instruction.
 * 기존의 시스템 호출 서비스는 인터럽트 핸들러(예를 들어 리눅스의 경우 int 0x80)가 담당하였으나, 
 * x86-64에서는 제조사가 시스템 호출을 요청하기 위한 효율적인 경로인 syscall 명령어를 제공합니다.
 *
 * The syscall instruction works by reading the values from the the Model Specific Register (MSR). For the details, see the manual. 
 * syscall 명령어는 MSR(Model Specific Register)에서 값을 읽음으로써 작동하며, 자세한 내용은 설명서를 참조하십시오. */

#define MSR_STAR 0xc0000081         /* Segment selector msr - 세그먼트 선택기 msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target - Long Mode 시스템 호출 대상 */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags - Eflags용 마스크 */

#define FDT_PAGES 3
#define FDCOUNT_LIMIT FDT_PAGES *(1 << 9)

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts until the syscall_entry swaps the userland stack to the kernel mode stack. Therefore, we masked the FLAG_FL.
	 * syscall_entry가 사용자 랜드 스택을 커널 모드 스택으로 스왑할 때까지 
	 * 인터럽트 서비스 루틴은 어떠한 인터럽트도 제공하지 않아야 하므로 FLAG_FL을 마스킹하였습니다. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface - 주 시스템 호출 인터페이스 */
void
syscall_handler (struct intr_frame *f UNUSED) {

	// System Call
	// 넘겨 받을 포인터 변수를 설정한다.
	int call_n = f->R.rax;

	// 받은 숫자에 맞춰서 case문을 통해 해당 시스템 콜을 호출해줘야 한다.
	switch (call_n) 
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			fork(f->R.rdi);
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// case SYS_WAIT:
		// 	wait(f->R.rdi);
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		// case SYS_OPEN:
		// 	open(f->R.rdi);
		// case SYS_FILESIZE:
		// 	filesize(f->R.rdi);
		// case SYS_READ:
		// 	read(f->R.rdi);
		// case SYS_WRITE:
		// 	write(f->R.rdi);
		// case SYS_SEEK:
		// 	seek(f->R.rdi);
		// case SYS_TELL:
		// 	tell(f->R.rdi);
		// case SYS_CLOSE:
		// 	close(f->R.rdi);
		default:
			exit(-1);
			break;
	}

	// printf ("system call!\n");
	// thread_exit ();
}

void
check_address (void *addr)	
{
	struct thread *cur = thread_current ();
	if (addr == NULL || !(is_user_vaddr (addr)) || pml4_get_page(cur->pml4, addr) == NULL) {
		exit(-1);
	}
}

void
halt (void) {
	power_off ();
}

void
exit (int status) {
	struct thread*curr = thread_current();

	curr->exit_status = status;

	// thread_name() - thread.c 파일에 curr->name을 반환하는 함수 
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}


// 프로세스 이름 받아 프로세스 복제 후 번호 반환.
tid_t 
fork (const char *thread_name) {
	// struct file *f = process_get_file(fd);

	// struct thread *curr = thread_current ();
	// return process_fork(thread_name, f);
}


int 
exec (const char *file) {
	// check_address(file);
	// int size = strnlen(file) +1;
	// char *fn_copy = palloc_get_page(PAL_ZERO);

	// if (fn_copy == NULL) {
	// 	exit(-1);
	// }

	// strlcpy (fn_copy, file, size);

	// if (process_exec (fn_copy) == -1) {
	// 	return -1;
	// }

	// NOT_REACHED ();
	// return 0;

	////////////////////////////////////////

	// char *cmd_line_copy;
	// cmd_line_copy = palloc_get_page(0);
	
	// if (cmd_line_copy == NULL) {
	// 	exit(-1);
	// }
	// strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	// if (process_exec(cmd_line_copy) == -1) {
	// 	exit(-1);
	// }
}

int 
wait (int pid) {
	return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool 
remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

// int 
// open (const char *file_name) {
// 	check_address(file_name);
// 	struct file *file = filesys_open(file_name);

// 	if (file == NULL) {
// 			return -1;
// 	}

// 	int fd = process_add_file(file);

// 	if (fd == -1) {
// 		file_close (file);
// 	}

// 	return fd;
// }

// int 
// filesize (int fd) {
// 	struct file *file = process_get_file(fd);

// 	if (file == NULL) {
// 		return -1;
// 	}

// 	return file_length(file);
// }

// int
// read (int fd, void *buffer, unsigned size) {
// 	check_address(buffer);
	

// 	char *ptr = (char *)buffer;
// 	int bytes_read = 0;

// 	lock_acquire(&filesys_done);

// 	if (fd == STDIN_FILENO)
// 	{
// 		for (int i = 0; i < size; i++)
// 		{
// 			char ch = input_getc();
// 			bytes_read++;
// 		}
// 		lock_release(&filesys_done);
// 	}
// 	else
// 	{
// 		if (fd < 2) {
// 			lock_release(&filesys_done);
// 			return -1;
// 		}

// 		struct file *file = process_get_file(fd);
		
// 		if (file == NULL) {
// 			lock_release(&filesys_done);
// 			return -1;
// 		}

// 		lock_acquire(&filesys_done);
// 		bytes_read = file_read(file, buffer, size);
// 		lock_release(&filesys_done);
// 	}
// 	return bytes_read;
// }

// int 
// write(int fd, const void *buffer, unsigned size) {
// 	check_address (buffer);
// 	lock_acquire(&filesys_done);

// 	int bytes_write = 0;
// 	if (fd == STDOUT_FILENO) {
// 		putbuf(buffer, size);
// 	}
// 	else {
// 		if (fd < 2) {
// 			lock_release(&filesys_done);
// 			return -1;
// 		}

// 		struct file *file = process_get_file(fd);

// 		if (file == NULL) {
// 			lock_release(&filesys_done);
// 			return -1;
// 		}
// 		bytes_write = file_write(file, buffer, size);
// 		lock_release(&filesys_done);
// 	}

// 	return bytes_write;
// }


void 
seek(int fd, unsigned position) {
	struct file *f = process_get_file(fd);

	if (fd > 2) {
		// /filesys/file.c 의 file_seek 함수 참조
		file_seek(f, position);
	}

	// struct file *file = process_add_file(fd);
	// if (file == NULL) {
	// 	return;
	// }

}

// // FILE의 현재 위치를 파일 시작부터 바이트 오프셋으로 반환
unsigned
tell (int fd) {
	struct file *f = process_get_file(fd);
	if (fd < 2) {
		return;
	}
	// struct file *file = process_get_file(fd);
	// if (file == NULL) {
	// 	return ;
	// }
	return file_tell(f); // /filesys/file.c의 file_tell (struct file *file) 참조
}

// void
// close (int fd) {
// 	if (fd < 2)
// 		return;

// 	struct file *file = process_get_file(fd);
	
// 	if (file == NULL) {
// 		return;
// 	}

// 	file_close(file);
// 	process_close_file(fd);
// }