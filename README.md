# debugging-linux-kernel
Learn about tracefs in linux kernel             
tracefs is a virtual filesystem in Linux that provides an interface for kernel tracing. It is designed to facilitate tracing and debugging of the kernel and its interactions with various components. The filesystem exposes tracing capabilities that allow users to monitor and analyze kernel events and function calls in a structured manner.

### Key Features of tracefs
*Centralized Interface for Tracing*: tracefs centralizes various tracing features in one filesystem, making it easier for users to access and configure tracing options.            
*Dynamic Tracing*: It allows dynamic tracing, meaning you can enable or disable specific trace events or functions at runtime without rebooting the system.
*Extensible*: tracefs supports various tracers and trace events, and it can be extended to include new tracing functionalities.

### Components of tracefs
When you mount tracefs, you typically see a directory structure under /sys/kernel/tracing or /sys/kernel/debug/tracing. Here are some key components:           
*available_events*: Lists all the trace events available in the kernel.             
*available_tracers*: Lists all the tracers that are compiled into the kernel.               
*current_tracer*: Allows you to set or get the current tracer being used.               
*trace*: This file contains the trace output, showing the logged events and function calls.             
*trace_pipe*: Provides a way to read the trace output in real-time.             
*events/*: Contains subdirectories for each subsystem, where you can enable or disable specific trace events.               
*options/*: Contains various options to configure tracing behavior.             
=> Almost using *echo/cat*


#### What is tracing?
A traditional debugger allows you to inspect the system state once the system is halted, after an error has been detected, but doesn’t reveal the events leading to the error. To understand why an event took place, the relevant context has to be restored. This requires tracing. Tracing is the process of collecting information on the activity in a working system. With tracing, program execution is recorded during run-time, allowing for later analysis of the trace. Tracing provides developers with information useful for debugging.

*Difference between tracing and logging??*            
Tracing is sometimes compared to logging. Just like logs, tracing data can be read as it is. With tracing, information is written about low-level events. These numbers in the hundreds or even thousands. With logging, information is written about higher-level events, which are much less frequent. These includes users logging into the system, application errors, database transaction etc.

#### Ftrace
Official Tracer of Linux Kernel. It let's you trace Linux Kernel function calls.
*Why do you need it?*       
Say you write a device driver, debug it, and confirm that everything’s fine. Then you run it inside the kernel and find that it’s not working as you expected, or something else breaks when you run it. With help of ftrace, you can  find out what functions are being called at kernel level and easily debug the issue.
*What can we do using ftrace?*          
Debugging Linux Kernel:         
	+ Analyzing Latencies in Linux Kernel           
	+ Learn and observe the flow of Linux Kernel            
	+ Trace context switches            
	+ Length of the time the interrupts are disabled            

#### Check ftrace enabled in kernel
Enabled in most distros by default      
Activated by Kernel Hacking -> Tracers      
Minimum kernel configuration required for ftrace            
```
cd /usr/src/linux-header-5.4.0-190-generic
make menuconfig
CONFIG_FTRACE --> "Tracers"
CONFIG_FUNCTION_TRACER --> Kernel Function Tracer
CONFIG_FUNCTION_GRAPH_TRACER --> Kernel Function Graph Tracer
CONFIG_STACK_TRACER	--> Traces Max stack
```
How to check whether ftrace is already enabled or not?        
```
cat /boot/config-`uname -r` | grep CONFIG_FTRACE
cat /boot/config-`uname -r` | grep CONFIG_FUNCTION_TRACER
cat /boot/config-`uname -r` | grep CONFIG_FUNCTION_GRAPH_TRACER
cat /boot/config-`uname -r` | grep CONFIG_STACK_TRACER
```
Most of the Linux distributions already provide ftrace, to check verify "tracing" directory exists or not.          
```
ls /sys/kernel/tracing
```
mount the tracefs by any of the two steps:          
1. Adding an entry into /etc/fstab:
```
 tracefs       /sys/kernel/tracing       tracefs defaults        0       0
```
2. Using the mount command:     
```
mount -t <filesystem_type> <device> <mount_point>
mount -t tracefs nodev /sys/kernel/tracing
```
After mounting tracefs, you will have access to the control and output files of ftrace.             
It was initially in debugfs(/sys/kernel/debug/tracing)          

#### Important files in tracefs
All manipulations are done with simple files operations (echo/cat) in tracefs. The ftrace is built around smart lockless ring buffer implementation. This buffer stores all the tracing information and is exposed as a file in tracefs available_tracers
Lists which tracers are configured important ones are:         
```
	nop	 	-	No Action (No Tracer Enabled)
	function 	-	Trace Kernel Functions Entry
	function_graph	-	Trace Kernel Functions Entry and Exit  thus allowing to build a call graph
	blk		-	Block Tracer/blktrace
	mmiotrace	-	Trace interactions between drivers and hardware
```
Default tracer is nop               
current_tracer file contain option tracing program presently is running.            

#### How to enable a tracer?
```
echo 'name of tracer' > current_tracer 
echo 'function' > current_tracer
echo 'function_graph' > current_tracer
echo 'nop' > current_tracer
```
Viewing the trace. 'trace' is the file where tracing data is saved in human-readable format
```
cat trace
```
Those are functions that are happening on the computer right now        
```
You can see from the cat output:
	First line specifies the tracer installed, in our case "function"
	Next each line prints the following information:
		Process Name
		PID
		CPU that the trace executed on
		Timestamp in seconds with the decimal places to microseconds. This timestamp is time since boot
		Function being traced
		Parent that call the function
```

#### Function Graph Tracer
Function Graph Tracer is built on top of Function Tracer.
It also records the return address. By this you will come to know when a function enters and function exits.
```
echo function_graph > current_tracer 
```
```
Function_graph tracer
	tracks the entry of the function
	tracks the exit of the function
	Execution Time
	CPU on which it is running
```
*Important Points*
```
Start of the function is denoted with '{' and end of the function is denoted with '}'. 
Functions that do not call any other functions, simply end with ';', also called as leaf functions
Duration column reports the time spent in the corresponding function. These numbers are only for the leaf functions, and the '}' symbol.

When the duration is greater than 10 microseconds, a '+' is shown in the DURATION column
When the duration is greater than 100 microseconds, a '-' is shown in DURATION column
When the duration is greater than 1000 microseconds, a '#' is shown in DURATION column
When the duration is greater than 10 milliseconds, a '*' is shown in DURATION column
When the duration is greater than 100 milliseconds, a '@' is shown in DURATION column
When the duration is greater than 1 seconds, a '$' is shown in DURATION column
```

#### Function Filtering
The ftrace printout can be big, and finding exactly what it is you're looking for can be extremely difficult. We can use filters to simplify our search. The printout will only display information about functions we're interested in.
```
cat available_filter_functions
```
*What functions are available for the filter?*
All the functions that can be traced are present in available_filter_functions. Limit What Functions you trace.             
If you want only enable few of the functions or disable few of the functions, then you can use the below files                  
```
set_ftrace_filter	-	Only trace these functions
set_ftrace_notrace	-	Do not trace these functions
(notrace takes precedence over filter)
```
Just echo function names into the files
```
echo function_name > set_ftrace_filter
```
Can add multiple (white space delimited)
```
echo function1 function2 > set_ftrace_filter
```
Append with the bash concatenation ">>"
```
echo function >> set_ftrace_filter
```
Clear with just writing nothing to it
```
echo > set_ftrace_notrace	
```
Example:
```
echo function > current_tracer
echo do_page_fault > set_ftrace_filter
cat trace

echo > set_ftrace_filter
echo kfree > set_ftrace_notrace
echo vfs_* > /sys/kernel/debug/tracing/set_ftrace_filter
echo schedule > set_ftrace_filter
```
set_ftrace_filter and set_ftrace_notrace affect function_graph as well
```
echo do_IRQ > set_ftrace_filter
echo function_graph > current_tracer
cat trace
```
This shows you the interrupt times, interrupt latencies of all the interrupts that are happening in your system.

#### Wild cards characters in filter
It supports minor wild cards "*" and "?"
```
value* - Will select all functions that start with string "value"
*value - Will select all functions that end with string "value"
*value* - Will select all functions that start and end with string "value"
Ex:
echo 'xen*' > set_ftrace_filter
echo '*lock*' > set_ftrace_filter
echo '*mutex*' > set_ftrace_filter
Extended glob matches (Started in 4.10)
echo '?raw_*lock' > set_ftrace_filter
```

#### Create module
hello.c
```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/delay.h>


int base_minor = 0;
char *device_name = "mychardev";
int count = 1;
dev_t devicenumber;

static struct class *class = NULL;
static struct device *device = NULL;
static struct cdev mycdev;

MODULE_LICENSE("GPL");

static int device_open(struct inode *inode, struct file *file)
{
	pr_info("%s\n", __func__);
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	pr_info("%s\n", __func__);
        return 0;
}

static ssize_t device_read(struct file *file, char __user *user_buffer,
                      size_t count, loff_t *offset)
{
	pr_info("%s:Count:%lu \t offset:%llu\n", __func__,
			count, *offset);
	msleep(1000);
        return 0;
}

static ssize_t device_write(struct file *file, const char __user *user_buffer,
                       size_t count, loff_t *offset)
{
	pr_info("%s:User Buffer:%s\t Count:%lu \t offset:%llu\n", __func__, user_buffer,
			count, *offset);
        return count;
}



struct file_operations device_fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};


static int test_hello_init(void)
{
	class = class_create(THIS_MODULE, "myclass");

	if (!alloc_chrdev_region(&devicenumber, base_minor, count, device_name)) {
		printk("Device number registered\n");
		printk("Major number received:%d\n", MAJOR(devicenumber));

		device = device_create(class, NULL, devicenumber, NULL, "mydevice");
		cdev_init(&mycdev, &device_fops);
		mycdev.owner = THIS_MODULE;
		cdev_add(&mycdev, devicenumber, count);

	}
	else
		printk("Device number registration Failed\n");

	return 0;
}

static void test_hello_exit(void)
{
	device_destroy(class, devicenumber);
        class_destroy(class);
	cdev_del(&mycdev);
	unregister_chrdev_region(devicenumber, count);
}

module_init(test_hello_init);
module_exit(test_hello_exit);
```
userapp.c
```
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define DEVICE_FILE	"/dev/mydevice"

int main()
{
	int fd;
	int retval;
	char buffer[10];

	printf("Opening File:%s\n", DEVICE_FILE);
	fd = open(DEVICE_FILE, O_RDWR);

	if (fd < 0) {
		perror("Open Failed");
		exit(1);
	}

	getchar();

	retval = write(fd, "hello", 5);
	printf("Write retval:%d\n", retval);
	getchar();

	retval = read(fd, buffer, 10);
	printf("Read retval:%d\n", retval);
	getchar();
	
	printf("Closing File\n");
	close(fd);
	getchar();

	return 0;
}
```
Makefile
```
obj-m += hello.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
*Install module*
```
make
sudo insmod ./hello.ko
dmesg
ls /dev/mydevice -l
sudo chmod 666 /dev/mydevice

make userapp
cat available_filter_functions | grep device_read
cat available_filter_functions | grep device_write
cat available_filter_functions | grep device_*

sudo rmmod hello
sudo insmod ./hello.ko (install again)
make userapp
sudo chmod 666 /dev/myevice

echo 'function' > current_tracer
echo 'device_open device_release device_read device_write' > set_ftrace_filter
./userapp
watch -n 0.1 -d 'cat trace' (to see the result after set and run userapp)
```

#### Starting and Stopping the trace
Suppose you only want to trace what is happening when you run a specific test, you can use tracing_on file. The file tracing_on is used to disable the ring buffer from recording data. Its a file, on/off switch. To make the ring buffer writeable or not.
```
[tracing]# echo 0 > tracing_on
```
Everything else still happens with the tracers and they will still incur most of their overhead. They do notice that the ring buffer is not recording and will not attempt to write any data, but the calls that the tracers make are still performed. To re-enable the ring buffer, simply write a '1' into that file:

```
[tracing]# echo 1 > tracing_on

A common run might be:
    [tracing]# echo 0 > tracing_on
    [tracing]# echo function_graph > current_tracer
    [tracing]# echo 1 > tracing_on; run_test; echo 0 > tracing_on
```
The first line disables the ring buffer from recording any data.            
The next enables the function graph tracer.         
The overhead of the function graph tracer is still present but nothing will be recorded into the trace buffer.          
The last line enables the ring buffer, runs the test program, then disables the ring buffer.            

#### trace vs trace_pipe
ftrace internally uses a ring buffer of fixed size. The size can be find out by reading "buffer_size_kb" file.  If the buffer becomes full, it will overwrite the starting tracing entries.         
```
cat buffer_size_kb
```
To read this ring buffer, we can cat either of the two files present in /sys/kernel/tracing folder:
```
trace
trace_pipe
```
trace is a non-consuming read. It pauses the tracing when you are reading                   
trace_pipe is consumer. It doesn't stop the tracing. Each time you read the contents of "trace" file it will print the same tracing entries, whereas with trace_pipe, each time you read the file the data is consumed, and in the next read data will be different also if there is no data trace_pipe will block.         
```
echo 0 > tracing_on
cat trace
cat trace
cat trace_pipe
cat trace_pipe
```

#### Filtering function graph tracing
set_graph_function:             
	Similar to set_ftrace_filter            
	Functions listed in this file will cause the function graph tracer to only trace these functions and the functions that they call           

*What's the benefit*
Useful to find out what calls made by a kernel function
```
echo vfs_read > set_graph_function
echo function_graph > current_tracer
```
set_graph_notrace: disable function graph tracing when the function is hit until it exits the function.

#### Tracing a specific Process
With ftrace, we can trace kernel calls only related to a specific process by echoing pid in the set_ftrace_pid file.            
Neat little trick to trace only, what you want.             
```
        echo 0 > tracing_on
        echo function > current_tracer
        sh -c 'echo $$ > set_ftrace_pid; echo 1 > tracing_on; exec myprog;'
Example

        sh -c 'echo $$ > set_ftrace_pid; echo 1 > tracing_on; exec echo hello;'
````
traceme.sh script
```
#!/bin/bash
DEBUGFS=`grep debugfs /proc/mounts | awk '{print $2;}'`
echo nop > $DEBUGFS/tracing/current_tracer
echo > $DEBUGFS/tracing/trace
echo $1
echo $$ > $DEBUGFS/tracing/set_ftrace_pid
echo function > $DEBUGFS/tracing/current_tracer
echo 1 > $DEBUGFS/tracing/tracing_on
exec $*
echo 0 > $DEBUGFS/tracing/tracing_on
```
```
traceme.sh ls
cat /sys/kernel/debug/tracing/trace | less
cat /sys/kernel/debug/tracing/trace > output
```
traceme-with-filter.sh script
```
#!/bin/bash

DEBUGFS=`grep debugfs /proc/mounts | awk '{print $2;}'`
echo nop > $DEBUGFS/tracing/current_tracer
echo > $DEBUGFS/tracing/trace
echo $1
echo $$ > $DEBUGFS/tracing/set_ftrace_pid
echo function > $DEBUGFS/tracing/current_tracer
echo vfs_* > /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > $DEBUGFS/tracing/tracing_on
exec $*
echo 0 > $DEBUGFS/tracing/tracing_on
``

#### Trace all functions related to a specific module
To trace all functions of a specific module, for example e1000 (Ethernet driver) you can pass the following to set_ftrace_filter.
```
echo ':mod:e1000' > set_ftrace_filter
cat set_ftrace_filter | head -n 10
ifconfig enp0s3 up
ifconfig enp0s3 down
```
traceme.sh
```
#!/bin/bash

DEBUGFS=`grep debugfs /proc/mounts | awk '{print $2;}'`
echo 0 > $DEBUGFS/tracing/tracing_on
echo nop > $DEBUGFS/tracing/current_tracer
echo > $DEBUGFS/tracing/trace
echo  > $DEBUGFS/tracing/set_ftrace_pid
echo function > $DEBUGFS/tracing/current_tracer
echo ':mod:e1000' > /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > $DEBUGFS/tracing/tracing_on
read enter
echo 0 > $DEBUGFS/tracing/tracing_on
```

#### trace_printk
printk() is the king of all debuggers, but it has a problem.            
	+ Using printk in interrupt context such as timer interrupts, scheduler, network can create a live lock
	+ Sometimes bug disappear when we add few printk's if something is time sensitive
	+ printk when writing to the serial console may take several milliseconds

With trace_printk           
	+ writing will be in the order of microseconds as it writes to a ring buffer instead of console
	+ can be used in any context (interrupt, scheduler, NMI Code)
	+ can be read via the 'trace' file

The performance advantage of trace_printk() lets you record the most sensitive areas of the kernel with very little impact.         
For example you can add something like this to the kernel or module:                
    trace_printk("Hello %s\n", "LWL");              

Note: trace_printk() output will appear in any tracer, even the function and function graph tracers.            

hello.c
```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

const unsigned char kbdus[128] =
{
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8',	/* 9 */
  '9', '0', '-', '=', '\b',	/* Backspace */
  '\t',			/* Tab */
  'q', 'w', 'e', 'r',	/* 19 */
  't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',	/* Enter key */
    0,			/* 29   - Control */
  'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',	/* 39 */
 '\'', '`',   0,		/* Left shift */
 '\\', 'z', 'x', 'c', 'v', 'b', 'n',			/* 49 */
  'm', ',', '.', '/',   0,				/* Right shift */
  '*',
    0,	/* Alt */
  ' ',	/* Space bar */
    0,	/* Caps lock */
    0,	/* 59 - F1 key ... > */
    0,   0,   0,   0,   0,   0,   0,   0,
    0,	/* < ... F10 */
    0,	/* 69 - Num lock*/
    0,	/* Scroll Lock */
    0,	/* Home key */
    0,	/* Up Arrow */
    0,	/* Page Up */
  '-',
    0,	/* Left Arrow */
    0,
    0,	/* Right Arrow */
  '+',
    0,	/* 79 - End key*/
    0,	/* Down Arrow */
    0,	/* Page Down */
    0,	/* Insert Key */
    0,	/* Delete Key */
    0,   0,   0,
    0,	/* F11 Key */
    0,	/* F12 Key */
    0,	/* All other keys are undefined */
};

MODULE_LICENSE("GPL");
static int irq = 1,  dev = 0xaa;
#define KBD_DATA_REG        0x60    /* I/O port for keyboard data */
#define KBD_SCANCODE_MASK   0x7f
#define KBD_STATUS_MASK     0x80

static irqreturn_t keyboard_handler(int irq, void *dev)
{
	char scancode;
	scancode = inb(KBD_DATA_REG);
	trace_printk("Character %c %s\n",
			kbdus[scancode & KBD_SCANCODE_MASK],
			scancode & KBD_STATUS_MASK ? "Released" : "Pressed");
        return IRQ_NONE;
}
/* registering irq */
static int test_interrupt_init(void)
{
        trace_printk("%s: In init\n", __func__);
        return request_irq(irq, keyboard_handler, IRQF_SHARED,"my_keyboard_handler", &dev);
}

static void test_interrupt_exit(void)
{
        trace_printk("%s: In exit\n", __func__);
        synchronize_irq(irq); /* synchronize interrupt */
        free_irq(irq, &dev);
}

module_init(test_interrupt_init);
module_exit(test_interrupt_exit);
```
Makefile
```
obj-m := hello.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```
*install module*
```
make
echo 1 > tracing_on
echo nop >current_tracer
rmmod hello
insmod hello.ko
cat trace_pipe
(typing any character to see the result)
```

#### Finding kernel functions taking > 10ms
ftrace uses 'tracing_thresh' file and compare the function duration if  greater than the value present in the file, it logs tracing entries in the ring buffer. By default the value is zero, it means ftrace doesn't care this. The value written in 'tracing_thresh' is in microseconds. So, if you want to find out the kernel functions which are taking more than 10ms , you need to write
```
echo '10000' > tracing_thresh
```
Set back zero in tracing_thresh, if you want to trace all the functions.
```
echo '0' > tracing_thresh
```

#### Finding out how user space code gets into kernel
We can find out what is the first kernel function called when the user space code gets into the kernel using 'max_graph_depth' file.            
Note: This can be used only with function_graph tracer.         
max_graph_depth file contains the maximum depth it will trace into a function.              
Default value: 0 - This means unlimited.                
If you 'echo 1 > max_graph_depth', it will only the trace the first function and ignore the other functions.        
```
cat trace
```
'do_syscall_64()' is the function through which the user space code gets into the kernel space.
If we want to find out the next function after 'do_syscall_64()':
```
# 'echo 2 > max_graph_depth'
echo 0 > tracing_on
echo 1 > max_graph_depth
echo function_graph > current_tracer
sh -c 'echo $$ > set_ftrace_pid; echo 1 > tracing_on; exec echo hello'
cat trace
```

#### Flags
```
# tracer: nop
#
# entries-in-buffer/entries-written: 79/79   #P:6
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
```
*irqs-off:*
'd' interrupts are disabled		
. otherwise		
hello.c
```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

const unsigned char kbdus[128] =
{
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8',	/* 9 */
  '9', '0', '-', '=', '\b',	/* Backspace */
  '\t',			/* Tab */
  'q', 'w', 'e', 'r',	/* 19 */
  't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',	/* Enter key */
    0,			/* 29   - Control */
  'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',	/* 39 */
 '\'', '`',   0,		/* Left shift */
 '\\', 'z', 'x', 'c', 'v', 'b', 'n',			/* 49 */
  'm', ',', '.', '/',   0,				/* Right shift */
  '*',
    0,	/* Alt */
  ' ',	/* Space bar */
    0,	/* Caps lock */
    0,	/* 59 - F1 key ... > */
    0,   0,   0,   0,   0,   0,   0,   0,
    0,	/* < ... F10 */
    0,	/* 69 - Num lock*/
    0,	/* Scroll Lock */
    0,	/* Home key */
    0,	/* Up Arrow */
    0,	/* Page Up */
  '-',
    0,	/* Left Arrow */
    0,
    0,	/* Right Arrow */
  '+',
    0,	/* 79 - End key*/
    0,	/* Down Arrow */
    0,	/* Page Down */
    0,	/* Insert Key */
    0,	/* Delete Key */
    0,   0,   0,
    0,	/* F11 Key */
    0,	/* F12 Key */
    0,	/* All other keys are undefined */
};

MODULE_LICENSE("GPL");
static int irq = 1,  dev = 0xaa;
#define KBD_DATA_REG        0x60    /* I/O port for keyboard data */
#define KBD_SCANCODE_MASK   0x7f
#define KBD_STATUS_MASK     0x80

static irqreturn_t keyboard_handler(int irq, void *dev)
{
	char scancode;
	scancode = inb(KBD_DATA_REG);
	trace_printk("Character %c %s\n",
			kbdus[scancode & KBD_SCANCODE_MASK],
			scancode & KBD_STATUS_MASK ? "Released" : "Pressed");
        return IRQ_NONE;
}
/* registering irq */
static int test_interrupt_init(void)
{
        trace_printk("%s: In init\n", __func__);
        return request_irq(irq, keyboard_handler, IRQF_SHARED,"my_keyboard_handler", &dev);
}

static void test_interrupt_exit(void)
{
        trace_printk("%s: In exit\n", __func__);
        synchronize_irq(irq); /* synchronize interrupt */
        free_irq(irq, &dev);
}

module_init(test_interrupt_init);
module_exit(test_interrupt_exit);
```
Makefile
```
obj-m := hello.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```
*need-resched:*
'N' both TIF_NEED_RESCHED and PREEMPT_NEED_RESCHED is set,
'n' only TIF_NEED_RESCHED is set,
'p' only PREEMPT_NEED_RESCHED is set,
'.' otherwise.

*hardirq/softirq:*			
'Z' - NMI occurred inside a hardirq			
'z' - NMI is running			
'H' - hard irq occurred inside a softirq.		
'h' - hard irq is running			
's' - soft irq is running			
'.' - normal context.			

*preempt-depth:*			
The level of preempt_disabled			
Any time kernel code holds a spinlock, preemption is disabled on the relevant processor			
Disabling preemtion is done by just incrementing the preempt_count for that process			
If the process's preempt_count is nonzero, then the process can not be preempted and this check is done			
while returning from system call and interrupt context			
Kernel preemption is disabled via preempt_disable() and enabled via preempt_enable().			
The call is nestable; you may call it any number of times. For each call, a corresponding call to preempt_enable() is required. The final corresponding call to preempt_enable()re-enables preemption.			
CONFIG_PREEMPT should bes set for this to work			
CONFIG_PREEMPT_VOLUNTARY			
Originally there were only two preemption options for the kernel: running with preemption on or off			
That setting was controlled by the kernel config option, CONFIG_PREEMPT		
In 2005,  a third option named CONFIG_PREEMPT_VOLUNTARY that was designed		
Nowadays, CONFIG_PREEMPT_VOLUNTARY is the default setting for pretty much all Linux distributions			
https://www.codeblueprint.co.uk/2019/12/23/linux-preemption-latency-throughput.html		

#### Start tracing on a particular function
We know 'tracing_on' file is used to disable/enable writing the traces on the ring buffer.
```
echo '0' > tracing_on //to disable tracing
echo '1' > tracing_on // to enable tracing
```
ftrace also provides functionality to start tracing on a particular function call execution or stop tracing on a particular function execution.				
Syntax: function:command[:count]			
The command will be executed on the start of the function. The value of command can be:				
	+ "traceon" to start the trace		
	+ "traceoff" to stop the trace			
	+ "stacktrace"			
The count is optional, specifies the number of times the command should be executed. If there is no count specified, the command will be executed each time the function is called.			
```
echo 'nop' > current_tracer
echo 'ksys_read:traceoff:1' > set_ftrace_filter
cat set_ftrace_filter
echo 'function' > current_tracer
```
*How to remove this?*
Using '!' operator
```
echo '!ksys_read:traceoff' > set_ftrace_filter
```

#### trace options
Modifies the way tracers may work

Modifies output format

Some tracers have their own options

Two ways to modify the options

- file trace_options

        shows only global or current tracer options

        to enable echo option_name > trace_options

        to disable echo nooption_name > trace_options

# cat trace_options
There are 27 options available for the user to control.			
The words which begin with "no" represents trace options that are disabled.			
Let's try few options			
1. sym-offset: Enabling this option, you will see function name plus offset in the function. By default, this is disabled.			
2. print-parent: This option displays the calling function. By default, this option is disabled.		
3. function-fork: This option enables tracing the children when set_ftrace_pid is set.			
4. irq-info: Displays the interrupt, preempt count, need resched data information in the trace.			
5. context-info: Disabling this option, will hide the Task-PID, CPU, Timestamp and other useful information.			

*options directory*
	+ shows global options		
	+ shows current tracer options		
	+ starting with v4.4 - shows all tracer options		
	+ to enable echo 1 > options/option_name		
	+ to disable echo 0 > options/option_name		
