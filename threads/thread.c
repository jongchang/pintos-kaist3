#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"

// mlfqs
#include "threads/fixed_point.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes that are ready to run but not actually running. 
 *  TRADE_READY 상태의 프로세스, 즉 실행 준비가 되었지만 실제로 실행되지 않는 프로세스의 목록입니다. */
static struct list ready_list;

// ticks에 도달하지 않은 스레드를 담을 연결 리스트 sleep_list 선언, thread_init에서 초기화
static struct list sleep_list;

// mlfqs
int load_avg;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&sleep_list); // sleep_list 리스트 초기화
	list_init (&destruction_req);
	
	// mlfqs
	list_init (&all_list);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	// mlfqs
	// load_avg = LOAD_AVG_DEFAULT;

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) { // 쓰레드를 생성, 초기화
	struct thread *t; // 쓰레드에 대한 정보를 담는 구조체
	tid_t tid; // 쓰레드 식별자

	ASSERT (function != NULL); // 함수 포인터 function이 NULL일 경우 잘못 호출

	/* Allocate thread. 스레드 할당. */
	t = palloc_get_page (PAL_ZERO); // 페이지 할당
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. 쓰레드 생성 시 우선순위 설정*/
	init_thread (t, name, priority); // thread 구조체 초기화
	tid = t->tid = allocate_tid (); // tid 할당 

	// System Call
	struct thread *curr = thread_current();
	list_push_back(&curr->child_list, &t->child_elem);
	// File Descriptor Table 메모리 할당 // palloc이나 malloc?
	t->fd_table = palloc_get_multiple(PAL_ZERO, FDT_PAGES);
	if(t->fd_table == NULL)
		return TID_ERROR;
	t->fd_idx = 2; // 0 : stdin, 1: stdout

	// /* Extra */
	t->fd_table[0] = 1; // dummy value? 
	t->fd_table[1] = 2;

	/* Call the kernel_thread if it scheduled. Note) rdi is 1st argument, and rsi is 2nd argument.
	 * 예정된 경우 kernel_thread를 호출합니다. 참고) rdi는 첫 번째 인수이고 rsi는 두 번째 인수입니다. */
	t->tf.rip = (uintptr_t) kernel_thread; // 쓰레드의 명령 포인터 레지스터(rip)를 커널 쓰레드의 함수의 주소로 설정(새 쓰레드으가 실행을 시작할 함수)
	t->tf.R.rdi = (uint64_t) function; // 실행할 함수의 주소
	t->tf.R.rsi = (uint64_t) aux;      // 함수에 전달될 두 번째 인수
	
	// 쓰레드 실행 시 올바른 메모리 세그먼트를 참조하고 권한을 갖도록 한다.
	// 설정된 세그먼트 선택자에 따라 쓰레드는 커널 영역에 접근하고 실행
	// SEL_KDSEG - 커널 데이터 세그먼트 선택자
	// SEL_KCSEG - 커널 코드 세그먼트 선택자
	t->tf.ds = SEL_KDSEG; // 쓰레드의 데이터 세그먼트
	t->tf.es = SEL_KDSEG; // 쓰레드의 에큐먼트 세그먼트
	t->tf.ss = SEL_KDSEG; // 쓰레드의 스텍 세그먼트
	t->tf.cs = SEL_KCSEG; // 쓰레드의 코드 세그먼트 - 실행 코드를 저장
	t->tf.eflags = FLAG_IF; // 쓰레드의 플래그 레지스터를 설정, FLAG_IF - 인터럽트를 활성하는 플래그 비트 설정

	/* Add to run queue. */
	thread_unblock (t);

	// 우선순위 처리
	// ready_list에 쓰레드를 삽입할 때 우선 순위를 현재 실행 중인 스레드와 비교한다.
	// 새로 도착한 쓰레드의 우선 순위가 높을 경우, 현재 실행 중인 쓰레드를 선점하고 새 쓰레드를 실행합니다.
	thread_test_preemption ();

    return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	// list_push_back (&ready_list, &t->elem); // delete
	/* 스레드가 unblocked되면 list_push_back 대신, 우선순위 순서대로 ready_list에 삽입한다. */
	list_insert_ordered(&ready_list, &t->elem, thread_compare_priority, NULL);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	// mlfqs
	list_remove(&thread_current()->allelem);

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and may be scheduled again immediately at the scheduler's whim. 
   CPU를 생성합니다. 현재 스레드가 절전 모드로 전환되지 않고 스케줄러의 충동에 따라 다시 예약할 수 있습니다. */
void
thread_yield (void) {
	struct thread *curr = thread_current (); // 현재 실행 중인 쓰레드
	enum intr_level old_level; // 인터럽트 레벨 - on / off

	ASSERT (!intr_context ()); // 외부 인터럽트가 들어올 경우 - True, 아닐 경우 - False

	old_level = intr_disable (); // 인터럽트를 비활성하, 이전 인터럽트 상태를 가져온다.
	if (curr != idle_thread) // 현재 쓰레드가 idle 쓰레드와 같지 않다면
		// list_push_back (&ready_list, &curr->elem); // ready 리스트 맨 마지막에 현재 리스트를 넣는다.
		list_insert_ordered(&ready_list, &curr->elem, thread_compare_priority, NULL); // 현재 쓰레드가 CPU 양보, ready_list에 우선순위 순서대로 삽입된다.
	do_schedule (THREAD_READY); // context switch 실행 - running 쓰레드를 ready 상태로 전환한다.
	intr_set_level (old_level); // 인자로 전달된 인터럽트 상태로 인터럽트 설정하고 이전 인터럽트 상태 변환한다.
}

//잠든 스레드를 sleep_list에 삽입하는 함수
// sleep_list에 ticks가 작은 스레드가 앞부분에 위치하도록 정렬하여 삽입한다.
void thread_sleep (int64_t wake_tick){
	struct thread *curr = thread_current();
	enum intr_level old_level;
	ASSERT (!intr_context());
	old_level = intr_disable();
	if( curr != idle_thread){
		//이시간에 일어나렴
		curr -> wakeup_tick = wake_tick;
		list_insert_ordered(&sleep_list, &curr->elem, cmp_thread_ticks, NULL);
		//리스트 푸시백 
		//레디리스트는 우선순위 정렬이 안되어있어서 뒤에 푸시한다.
	}
	do_schedule (THREAD_BLOCKED);
	intr_set_level(old_level);
}

void thread_wake(int64_t elapsed) {

	while (!list_empty(&sleep_list) && list_entry(list_front(&sleep_list), struct thread, elem)->wakeup_tick <= elapsed) {
			struct list_elem *front_elem = list_pop_front(&sleep_list);
			thread_unblock(list_entry(front_elem, struct thread, elem));
	}
}


/* Sets the current thread's priority to NEW_PRIORITY. - 현재 쓰레드의 우선 순위를 설정한다. */
void
thread_set_priority (int new_priority) {
	// mlfqs
	if (thread_mlfqs)
		return;

	// thread_current ()->priority = new_priority;
	thread_current ()->init_priority = new_priority;

	refresh_priority ();
	thread_test_preemption(); // ready_list 재정렬한다. = 우선 순위가 변경될 경우, cpu가 점유하는 쓰레드가 변경된다. 
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. 현재 쓰레드의 nice 변경 */
void
thread_set_nice (int nice UNUSED) {
	// mlfqs
	enum intr_level old_level = intr_disable ();
    thread_current ()->nice = nice;
    mlfqs_calculate_priority (thread_current ());
    thread_test_preemption ();
    intr_set_level (old_level);
}

/* Returns the current thread's nice value. 현재 쓰레드의 nice 반환 */
int
thread_get_nice (void) {
	// mlfqs
	enum intr_level old_level = intr_disable ();
    int nice = thread_current ()-> nice;
    intr_set_level (old_level);
    return nice;
}

/* Returns 100 times the system load average. Pint OS의 load_avg * 100 반환 */
int
thread_get_load_avg (void) {
	enum intr_level old_level = intr_disable ();
    int load_avg_value = fp_to_int_round (mult_mixed (load_avg, 100));
    intr_set_level (old_level);
    return load_avg_value;
}

/* Returns 100 times the current thread's recent_cpu value. 현재 쓰레드의 recent_cpu * 100 반환 */
int
thread_get_recent_cpu (void) {
	enum intr_level old_level = intr_disable ();
    int recent_cpu= fp_to_int_round (mult_mixed (thread_current ()->recent_cpu, 100));
    intr_set_level (old_level);
    return recent_cpu;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;

	/* priority-donate - 쓰레드 해더파일에 작성한 새 요소들을 초기화한다. */
	t->init_priority = priority;
    t->wait_on_lock = NULL;
    list_init (&t->donations);

	// mlfqs
	t->nice = NICE_DEFAULT;
    t->recent_cpu = RECENT_CPU_DEFAULT;
	list_push_back(&all_list, &t->allelem);

	// System Call
	t->exit_status = 0;
	t->next_fd = 2;

	// sema_init(&t->load_sema, 0);
	// sema_init(&t->exit_sema, 0);
	sema_init(&t->wait_sema, 0);
	sema_init(&t->free_sema, 0);
	sema_init(&t->fork_sema, 0);

	list_init(&(t->child_list));
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

bool cmp_thread_ticks(struct list_elem *a_ ,struct list_elem *b_, void *aux UNUSED){
	const struct thread *a = list_entry(a_, struct thread, elem);
	const struct thread *b = list_entry(b_, struct thread, elem);
	return(a->wakeup_tick < b->wakeup_tick);
}

// 현재 쓰레드보다 ready_list의 헤드가 우선순위가 높을 경우
void thread_test_preemption (void) {
	if (list_empty(&ready_list)) {
		return;
	}
	struct list_elem *highest_priority_e = list_begin(&ready_list);
	struct thread *highest_priority_t = list_entry(highest_priority_e, struct thread, elem);
	if (thread_current()->priority < highest_priority_t->priority) {
		thread_yield();
	}
}

// a가 b보다 우선순위가 높을 경우 true를 반환
bool 
thread_compare_priority (const struct list_elem* a_elem, const struct list_elem *b_elem, void* aux UNUSED) {
	struct thread* thread_a = list_entry(a_elem, struct thread, elem);
	struct thread* thread_b = list_entry(b_elem, struct thread, elem);
	
	return thread_a->priority > thread_b->priority;

}

// doantion 리스트의 요소의 우선순위를 비교하는 함수
bool
thread_compare_donate_priority (const struct list_elem *l, const struct list_elem *s, void *aux UNUSED) {
	return list_entry (l, struct thread, donation_elem)->priority > list_entry (s, struct thread, donation_elem)->priority;
}

void
donate_priority (void) {
    int depth;
    struct thread *cur = thread_current ();

    for (depth = 0; depth < 8; depth++){
		if (!cur->wait_on_lock) break;
		struct thread *holder = cur->wait_on_lock->holder;
		holder->priority = cur->priority;
		cur = holder;
    }
}

void
remove_with_lock (struct lock *lock)
{
    struct list_elem *e;
    struct thread *cur = thread_current ();

    for (e = list_begin (&cur->donations); e != list_end (&cur->donations); e = list_next (e)){
		struct thread *t = list_entry (e, struct thread, donation_elem);
		if (t->wait_on_lock == lock)
			list_remove (&t->donation_elem);
    }
}

void
refresh_priority (void) {
    struct thread *cur = thread_current ();
    cur->priority = cur->init_priority;

    if (!list_empty (&cur->donations)) {
		list_sort (&cur->donations, thread_compare_donate_priority, 0);

    	struct thread *front = list_entry (list_front (&cur->donations), struct thread, donation_elem);
		if (front->priority > cur->priority)
			cur->priority = front->priority;
    }
}

// mlfqs의 우선순위를 계산
void
mlfqs_calculate_priority (struct thread *t)
{
    if (t == idle_thread) 
   		return;
    t->priority = fp_to_int (add_mixed (div_mixed (t->recent_cpu, -4), PRI_MAX - t->nice * 2));
}

// 쓰레드의 recent_cpu를 계산
void
mlfqs_calculate_recent_cpu (struct thread *t)
{
    if (t == idle_thread)
    	return ;
    t->recent_cpu = add_mixed (mult_fp (div_fp (mult_mixed (load_avg, 2), add_mixed (mult_mixed (load_avg, 2), 1)), t->recent_cpu), t->nice);
}

// Pint OS의 load_avg 값을 계산
void
mlfqs_calculate_load_avg (void) 
{
    int ready_threads;
  
    if (thread_current () == idle_thread)
    	ready_threads = list_size (&ready_list);
  	else
    	ready_threads = list_size (&ready_list) + 1;

    load_avg = add_fp (mult_fp (div_fp (int_to_fp (59), int_to_fp (60)), load_avg), mult_mixed (div_fp (int_to_fp (1), int_to_fp (60)), ready_threads));
}

// 현재 쓰레드의 recent_cpu 1증가
void
mlfqs_increment_recent_cpu (void)
{
  	if (thread_current () != idle_thread)
    	thread_current ()->recent_cpu = add_mixed (thread_current ()->recent_cpu, 1);
}

// 전체 쓰레드의 recent_cpu를 재계산
void
mlfqs_recalculate_recent_cpu (void)
{
  	struct list_elem *e;
  	for (e = list_begin (&all_list); e != list_end (&all_list); e = list_next (e)) {
    	struct thread *t = list_entry (e, struct thread, allelem);
    	mlfqs_calculate_recent_cpu (t);
  	}
}

// 전체 쓰레드의 우선순위 재계산
void
mlfqs_recalculate_priority (void)
{
    struct list_elem *e;
    for (e = list_begin (&all_list); e != list_end (&all_list); e = list_next (e)) {
    	struct thread *t = list_entry (e, struct thread, allelem);
    	mlfqs_calculate_priority (t);
  	}
}