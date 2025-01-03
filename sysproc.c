#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}


int
sys_settrace(void)
{
  int enable;
  if(argint(0, &enable) < 0)
    return -1;
  myproc()->trace = enable;
  return 0;
}


int 
sys_setflag(void){
  int flagIndex ;
  int sysCallIndex ; 

  if(argint(0, &flagIndex) < 0)
    return -1;

  if(argint(1, &sysCallIndex) < 0)
    return -1;

  myproc()->flagIndex = flagIndex;
  myproc()->sysCallIndex = sysCallIndex;

  return 0;

}

int
sys_printonshell(void)
{
  int enable;
  if(argint(0, &enable) < 0)
    return -1;
  myproc()->printonshell = enable;
  return 0;
}


int
sys_tracerun(void)
{
  char *argument1;
  char *argument2;

  // Retrieve the first string argument
  if(argstr(0, &argument1) < 0)
    return -1;

  // Retrieve the second string argument
  if(argstr(1, &argument2) < 0)
    return -1;

  // Use argument1 and argument2 as needed
  // For example, you could store them in the proc struct, print them, etc.
  // myproc()->someStringField1 = argument1;
  // myproc()->someStringField2 = argument2;
  
  return 0;
}
