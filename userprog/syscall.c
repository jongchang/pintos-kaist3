#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/* 추가해준 헤더 파일들 */
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"

struct lock filesys_lock;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* syscall functions */
void halt (void);
void exit (int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
int _write (int fd UNUSED, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork (const char *thread_name);
int exec (const char *file_name);

/* syscall helper functions */
void check_address(const uint64_t*);
struct file *process_get_file(int fd);
int process_add_file(struct file *file);
void process_close_file(int fd);

/* Project2-extra */
const int STDIN = 1;
const int STDOUT = 2;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	/* LOCK INIT 추가*/
	lock_init(&filesys_lock);
}

/* helper functions letsgo ! */
void check_address(const uint64_t* addr){
	struct thread *t = thread_current(); // 변경사항
	/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
	/* what if the user provides an invalid pointer, a pointer to kernel memory, 
	 * or a block partially in one of those regions */
	/* 잘못된 접근인 경우, 프로세스 종료 */
	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4, addr) == NULL)
		exit(-1);
} 

int process_add_file(struct file *f){
	struct thread *curr = thread_current();
	struct file **curr_fd_table = curr->fd_table;
	for (int idx = curr->fd_idx; idx < FDCOUNT_LIMIT; idx++){
		if(curr_fd_table[idx] == NULL){
			curr_fd_table[idx] = f;
			curr->fd_idx = idx; // fd의 최대값 + 1 // 논란있을듯???
			return curr->fd_idx;
		}
	}
	curr->fd_idx = FDCOUNT_LIMIT;
	return -1;
}

struct file *process_get_file (int fd){
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;
	struct file *f = thread_current()->fd_table[fd];
	return f;
}

/* revove the file(corresponding to fd) from the FDT of current process */
void process_close_file(int fd){
	if (fd < 0 || fd > FDCOUNT_LIMIT)
		return NULL;
	thread_current()->fd_table[fd] = NULL;
}

/* helper functions gooooooooooood job */

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_num = f->R.rax; // rax: system call number
	switch(syscall_num){
		case SYS_HALT:                   /* Halt the operating system. */
			halt();
			break;
		case SYS_EXIT:                   /* Terminate this process. */
			exit(f->R.rdi);
			break;    
		case SYS_FORK:   ;                /* Clone current process. */
			struct thread *curr = thread_current();
			memcpy(&curr->parent_if, f, sizeof(struct intr_frame));
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:                   /* Switch current process. */
			if (exec(f->R.rdi) == -1)
				exit(-1);
			break;
		case SYS_WAIT:                   /* Wait for a child process to die. */
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:                 /* Create a file. */
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:                 /* Delete a file. */
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:                   /* Open a file. */
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:               /* Obtain a file's size. */
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:                   /* Read from a file. */
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:                  /* Write to a file. */
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:                   /* Change position in a file. */
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:                   /* Report current position in a file. */
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:					 /* Close a file. */
			close(f->R.rdi);
			break;
		default:						 /* call thread_exit() ? */
			exit(-1);
			break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}

//변경사항 

/* halt the operating system */ 
void halt(void){
	power_off(); // init.c의 power_off 활용
}

/* terminate this process */
void exit(int status){
	struct thread *curr = thread_current(); // 실행 중인 스레드 구조체 가져오기
	curr->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status); // if status != 0, error
	thread_exit(); // 스레드 종료
}

/* Clone current process. */
tid_t fork (const char *thread_name){
	/* create new process, which is the clone of current process with the name THREAD_NAME*/
	struct thread *curr = thread_current();
	return process_fork(thread_name, &curr->parent_if);
	/* must return pid of the child process */
}

int exec (const char *file){
	check_address(file);
	int size = strlen(file) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	
	if(fn_copy==NULL)
		exit(-1);
	//palloc 쓰는 이유 좀 더 고민해보기(아마 paging과 연관)
	strlcpy(fn_copy, file, size);
	if (process_exec(fn_copy) == -1)
		return -1;

	NOT_REACHED();
	return 0;
}

/* Wait for a child process to die. */
int wait(tid_t pid){
	process_wait(pid);
}

 /* Create a file. */
bool create(const char *file, unsigned initial_size){
	check_address(file); // 포인터가 가리키는 주소가 유저영역의 주소인지 확인
	return filesys_create(file, initial_size); // 파일 이름 & 크기에 해당하는 파일 생성
}

 /* Delete a file. */
bool remove(const char *file){
	check_address(file); // 포인터가 가리키는 주소가 유저영역의 주소인지 확인
	return filesys_remove(file); // 파일 이름에 해당하는 파일을 제거
}

int open (const char *file){
	check_address(file);
	lock_acquire(&filesys_lock);
	struct file *f = filesys_open(file); // 파일을 오픈
	if (f == NULL)
		return -1;
	int fd = process_add_file(f);
	if (fd == -1)
		file_close(f);
	lock_release(&filesys_lock);
	return fd;
}


int filesize (int fd){
	struct file *f = process_get_file(fd); // fd를 이용해서 파일 객체 검색
	if (f == NULL) return -1;
	return file_length(f);
}

/* 수정완료 */
int read (int fd, void *buffer, unsigned size){
	check_address(buffer);
	unsigned char *buf = buffer;
	int readsize;

	struct file *f = process_get_file(fd);

	if (f == NULL) return -1;
	if (fd < 0 || fd>= FDCOUNT_LIMIT) return NULL;
	if (f == STDOUT) return -1;
	
	if (f == STDIN){
		for (readsize = 0; readsize < size; readsize++){
			char c = input_getc();
			*buf++ = c;
			if (c == '\0')
				break;
		}
	}
	else{
		lock_acquire(&filesys_lock); // 파일에 동시접근 일어날 수 있으므로 lock 사용
		readsize = file_read(f, buffer, size);
		lock_release(&filesys_lock);
	}
	return readsize;
}

/* 수정완료 */
int write (int fd, const void *buffer, unsigned size){ // length->size로 수정 (맞춰수정?)
	check_address(buffer);
	struct file *f = process_get_file(fd);
	int writesize;

	if (f == NULL) return -1;
	if (f == STDIN) return -1;

	if (f == STDOUT){
		putbuf(buffer, size);// buffer에 들은 size만큼을, 한 번의 호출로 작성해준다.
		writesize = size;
	}
	else{
		lock_acquire(&filesys_lock); // 파일에 동시접근 일어날 수 있으므로 lock 사용
		writesize = file_write(f, buffer, size);
		lock_release(&filesys_lock);
	}
	return writesize;
}

void seek (int fd, unsigned position){
	struct file *f = process_get_file(fd);
	if (f > 2)
		file_seek(f, position);
}

unsigned tell (int fd){
	struct file *f = process_get_file(fd);
	if (fd < 2)
		return;
	return file_tell(f);
}

void close (int fd){
	if(fd < 2) return;
	struct file *f = process_get_file(fd);

	if(f == NULL)
		return;
	/* 여긴 그냥 fd < 2로도 가능할듯 */
	process_close_file(fd);
	file_close(f);
}