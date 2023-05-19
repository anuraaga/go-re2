	.text

	.export_name	wasi_thread_init, wasi_thread_init

	.globaltype	__stack_pointer, i32
	.globaltype	__tls_base, i32

	.hidden	wasi_thread_init
	.globl	wasi_thread_init
	.type	wasi_thread_init,@function

wasi_thread_init:
	.functype	wasi_thread_init (i32, i32) -> ()

	# Set up the minimum C environment.
	local.get   0
	global.set  __tls_base

	local.get   1
	global.set  __stack_pointer

	end_function
