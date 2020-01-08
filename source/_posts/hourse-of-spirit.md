---
title: hourse of spirit
date: 2020-01-08 17:02:45
tags:
	- thinking
---

### 原理解释
&emsp;&emsp;House of spirit是the malloc Maleficarum的一种技术。该技术的核心思想是伪造fastbin chunk并将其释放，从而达到分配任意地址的chunk的目的。
想要伪造fastbin fake chunk，主要需要绕过free时对其进行的检查：

- fake chunk的ISMMAP位不能为1，因为free时，如果是mmap的chunk，则会进行单独处理。
- fake chunk的地址需要对齐，MALLOC_ALIGN_MASK
- fake chunk的size大小需要满足fastbin的要求，也需要对齐
- fake chunk的nextchunk的大小不能小于2 * size_se，也不能大于av->system_mem
- fake chunk对应的fastbin head不能为该chunk，否则会触发double free

相关源码如下：
```c
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  
  // 检查大小是否大于最小的chunk，是否对齐
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);
  
  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */
  // 检查该chunk是否符合fastbin
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())) {

		// 检查nextchunk的size是否小于最小chunk要求，或大于系统最大chunk
    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	bool fail = true;
		/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	  // 检查是否有lock
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }
    // 将chunk的mem部分设置为perturb_byte
    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);
    
    // 设置fastbin标记位
    atomic_store_relaxed (&av->have_fastchunks, true);
    
    // 获取对应fastbin的头指针
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    // 使用原子操作将该chunk插入其中
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
  // 检查上一次插入的chunk是否与p相同，若相同则为double free
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = old;
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  p->fd = old2 = old;
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);

    /* Check that size of fastbin chunk at the top is the same as
       size of the chunk that we are adding.  We can dereference OLD
       only if we have the lock, otherwise it might have already been
       allocated again.  */
    // 确保插入前后相同
    if (have_lock && old != NULL
	&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
      malloc_printerr ("invalid fastbin entry (free)");
  }  
```

下面我们来做一道题看看

### OREO

Basic Info：
```shell
[*] '/ctf/work/pwn/fastbin/oreo/oreo'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
该程序的大概逻辑是这样的，这是一个枪支系统。枪支的结构体如下：
```shell
00000000 rifle           struc ; (sizeof=0x38, mappedto_5)
00000000 descript        db 25 dup(?)
00000019 name            db 27 dup(?)
00000034 prev            dd ?                    ; offset
00000038 rifle           ends
```

大概功能如下：
1. 添加枪支功能

```c
void add_rifles(void)
{
    int32_t iVar1;
    undefined4 uVar2;
    int32_t in_GS_OFFSET;
    int32_t var_10h;
    int32_t var_ch;
    
    uVar2 = _rifles_head;
    iVar1 = *(int32_t *)(in_GS_OFFSET + 0x14);
    _rifles_head = sym.imp.malloc(0x38);
    if (_rifles_head == 0) {
        sym.imp.puts("Something terrible happened!");
    } else {
        *(undefined4 *)(_rifles_head + 0x34) = uVar2;
        sym.imp.printf("Rifle name: ");
        sym.imp.fgets(_rifles_head + 0x19, 0x38, _section..bss);
        add_End(_rifles_head + 0x19);
        sym.imp.printf("Rifle description: ");
        sym.imp.fgets(_rifles_head, 0x38, _section..bss);
        add_End(_rifles_head);
        _rifles_counts = _rifles_counts + 1;
    }
    if (iVar1 != *(int32_t *)(in_GS_OFFSET + 0x14)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}


```
大致流程是首先将rifles_head储存起来，然后分配一个新的chunk来储存rifles struct，把rifles_head存到0x34的位置把name存到0x19的位置，desc存到开始的位置，然后rifles_count(0x804a2a4)++.
这样以来rifles就形成了一条链表。

我们注意到name和desc读入的size都是0x38这里明显存在溢出。

> 其中add_End()函数是想字符串尾加一个‘\0'

```c
void add_End(int32_t arg_8h)
{
    int32_t iVar1;
    int32_t iVar2;
    char *pcVar3;
    int32_t in_GS_OFFSET;
    int32_t var_1ch;
    int32_t var_10h;
    int32_t var_ch;
    
    iVar1 = *(int32_t *)(in_GS_OFFSET + 0x14);
    iVar2 = sym.imp.strlen(arg_8h);
    pcVar3 = (char *)(arg_8h + iVar2 + -1);
    if (((uint32_t)arg_8h <= pcVar3) && (*pcVar3 == '\n')) {
        *pcVar3 = '\0';
    }
    if (iVar1 != *(int32_t *)(in_GS_OFFSET + 0x14)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

2. 查看所有枪支

```c
void show_added_rifles(void)
{
    int32_t iVar1;
    int32_t in_GS_OFFSET;
    int32_t var_14h;
    int32_t var_10h;
    int32_t var_ch;
    
    iVar1 = *(int32_t *)(in_GS_OFFSET + 0x14);
    sym.imp.printf("Rifle to be ordered:\n%s\n", 0x8048bb0);
    var_14h = _rifles_head;
    while (var_14h != 0) {
        sym.imp.printf("Name: %s\n", var_14h + 0x19);
        sym.imp.printf("Description: %s\n", var_14h);
        sym.imp.puts(0x8048bb0);
        var_14h = *(int32_t *)(var_14h + 0x34);
    }
    if (iVar1 != *(int32_t *)(in_GS_OFFSET + 0x14)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

该函数会遍历rifles链表,然后打印name和desc

3. free所有的rifles

```c
void order_rifles(void)
{
    int32_t iVar1;
    int32_t iVar2;
    int32_t in_GS_OFFSET;
    int32_t var_14h;
    int32_t var_10h;
    int32_t var_ch;
    
    iVar1 = *(int32_t *)(in_GS_OFFSET + 0x14);
    var_14h = _rifles_head;
    if (_rifles_counts == 0) {
        sym.imp.puts("No rifles to be ordered!");
    } else {
        while (var_14h != 0) {
            iVar2 = *(int32_t *)(var_14h + 0x34);
            sym.imp.free(var_14h);
            var_14h = iVar2;
        }
        _rifles_head = 0;
        _order_counts = _order_counts + 1;
        sym.imp.puts("Okay order submitted!");
    }
    if (iVar1 != *(int32_t *)(in_GS_OFFSET + 0x14)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```

这里我们可以看到这个函数会free链表上所有的rifles结构，但是没有设置为NULL

4. leave message

```c
void leave_message(void)
{
    int32_t iVar1;
    int32_t in_GS_OFFSET;
    int32_t var_ch;
    
    iVar1 = *(int32_t *)(in_GS_OFFSET + 0x14);
    sym.imp.printf("Enter any notice you\'d like to submit with your order: ");
    sym.imp.fgets(_message, 0x80, _section..bss);
    add_End(_message);
    if (iVar1 != *(int32_t *)(in_GS_OFFSET + 0x14)) {
    // WARNING: Subroutine does not return
        sym.imp.__stack_chk_fail();
    }
    return;
}
```
这里会向message(0x804a2a8)这里写入一段内容



































