//go:build !tinygo.wasm && !re2_cgo

package internal

import (
	"container/list"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

var (
	errFailedWrite = errors.New("failed to read from wasm memory")
	errFailedRead  = errors.New("failed to read from wasm memory")
)

type contextKey string

var (
	contextKeyExitCh = contextKey("exit-channel")
	contextKeyModCh  = contextKey("mod-channel")
)

//go:embed wasm/libcre2.so
var libre2 []byte

//go:embed wasm/memory.wasm
var memoryWasm []byte

type modHolder struct {
	mod    api.Module
	exitCh chan struct{}
}

var (
	wasmRT       wazero.Runtime
	wasmCompiled wazero.CompiledModule
	wasmMemory   api.Memory
	rootMod      api.Module

	modPool   *list.List
	modPoolMu sync.Mutex
)

type libre2ABI struct {
	cre2New                   lazyFunction
	cre2Delete                lazyFunction
	cre2Match                 lazyFunction
	cre2NumCapturingGroups    lazyFunction
	cre2ErrorCode             lazyFunction
	cre2ErrorArg              lazyFunction
	cre2NamedGroupsIterNew    lazyFunction
	cre2NamedGroupsIterNext   lazyFunction
	cre2NamedGroupsIterDelete lazyFunction
	cre2GlobalReplace         lazyFunction
	cre2OptNew                lazyFunction
	cre2OptDelete             lazyFunction
	cre2OptSetLogErrors       lazyFunction
	cre2OptSetLongestMatch    lazyFunction
	cre2OptSetPosixSyntax     lazyFunction
	cre2OptSetCaseSensitive   lazyFunction
	cre2OptSetLatin1Encoding  lazyFunction

	malloc lazyFunction
	free   lazyFunction

	mod api.Module
	mu  sync.Mutex
}

var prevTID uint32

type childModule struct {
	mod        api.Module
	tlsBasePtr uint32
	exitCh     chan struct{}
}

func createChildModule(rt wazero.Runtime, root api.Module) *childModule {
	ctx := context.Background()

	// Not executing function so is at end of stack
	stackPointer := root.ExportedGlobal("__stack_pointer").Get()
	tlsBase := root.ExportedGlobal("__tls_base").Get()

	// Thread-local-storage for the main thread is from __tls_base to __stack_pointer
	// For now, let's preserve the size but in the future we can probably use less.
	size := stackPointer - tlsBase

	malloc := root.ExportedFunction("malloc")

	// Allocate memory for the child thread stack
	res, err := malloc.Call(ctx, size)
	if err != nil {
		panic(err)
	}
	ptr := uint32(res[0])

	child, err := rt.InstantiateModule(ctx, wasmCompiled, wazero.NewModuleConfig().
		// Don't need to execute start functions again in child, it crashes anyways.
		WithStartFunctions())
	if err != nil {
		panic(err)
	}
	initTLS := child.ExportedFunction("__wasm_init_tls")
	if _, err := initTLS.Call(ctx, uint64(ptr)); err != nil {
		panic(err)
	}

	tid := atomic.AddUint32(&prevTID, 1)
	root.Memory().WriteUint32Le(ptr, ptr)
	root.Memory().WriteUint32Le(ptr+20, tid)
	child.ExportedGlobal("__stack_pointer").(api.MutableGlobal).Set(uint64(ptr) + size)

	ret := &childModule{
		mod:        child,
		tlsBasePtr: ptr,
	}
	runtime.SetFinalizer(ret, func(obj interface{}) {
		cm := obj.(*childModule)
		free := cm.mod.ExportedFunction("free")
		if _, err := free.Call(ctx, uint64(cm.tlsBasePtr)); err != nil {
			panic(err)
		}
		_ = cm.mod.Close(context.Background())
	})
	return ret
}

func createChildModuleWASI(root api.Module) *childModule {
	exitCh := make(chan struct{})
	modCh := make(chan api.Module)
	ctx := context.WithValue(context.Background(), contextKeyExitCh, exitCh)
	ctx = context.WithValue(ctx, contextKeyModCh, modCh)
	if _, err := root.ExportedFunction("wasi_start_thread").Call(ctx); err != nil {
		panic(err)
	}
	child := <-modCh
	ret := &childModule{
		mod:    child,
		exitCh: exitCh,
	}
	runtime.SetFinalizer(ret, func(obj interface{}) {
		cm := obj.(*childModule)
		close(cm.exitCh)
	})
	return ret
}

func getChildModule() *childModule {
	modPoolMu.Lock()
	defer modPoolMu.Unlock()
	if modPool.Len() == 0 {
		return createChildModule(wasmRT, rootMod)
	}
	e := modPool.Front()
	modPool.Remove(e)
	return e.Value.(*childModule)
}

func putChildModule(cm *childModule) {
	modPoolMu.Lock()
	defer modPoolMu.Unlock()
	modPool.PushBack(cm)
}

func init() {
	ctx := context.Background()
	//f, _ := os.Create("trace.txt")
	//lf := logging.NewLoggingListenerFactory(f)
	//ctx = context.WithValue(ctx, experimental.FunctionListenerFactoryKey{}, lf)
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCoreFeatures(api.CoreFeaturesV2|experimental.CoreFeaturesThreads))

	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	if _, err := rt.InstantiateWithConfig(ctx, memoryWasm, wazero.NewModuleConfig().WithName("env")); err != nil {
		panic(err)
	}

	if _, err := rt.NewHostModuleBuilder("wasi").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			tid := atomic.AddUint32(&prevTID, 1)
			childStack := make([]uint64, 2)
			childStack[0] = uint64(tid)
			childStack[1] = stack[0]
			child, err := rt.InstantiateModule(ctx, wasmCompiled, wazero.NewModuleConfig().WithStartFunctions().WithName(""))
			if err != nil {
				panic(err)
			}
			go func() {
				if err := child.ExportedFunction("wasi_thread_start").CallWithStack(ctx, childStack); err != nil {
					panic(err)
				}
			}()
			stack[0] = uint64(tid)
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("thread-spawn").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			exitCh := ctx.Value(contextKeyExitCh).(chan struct{})
			modCh := ctx.Value(contextKeyModCh).(chan api.Module)
			modCh <- m
			<-exitCh
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		Export("thread-block").
		Instantiate(ctx); err != nil {
		panic(err)
	}

	code, err := rt.CompileModule(ctx, libre2)
	if err != nil {
		panic(err)
	}
	wasmCompiled = code

	wasmRT = rt
	root, err := wasmRT.InstantiateModule(ctx, wasmCompiled, wazero.NewModuleConfig().WithStartFunctions("_initialize").WithName(""))
	if err != nil {
		panic(err)
	}
	wasmMemory = root.Memory()
	rootMod = root

	modPool = list.New()
}

func newABI() *libre2ABI {
	abi := &libre2ABI{
		cre2New:                   newLazyFunction(wasmRT, "cre2_new"),
		cre2Delete:                newLazyFunction(wasmRT, "cre2_delete"),
		cre2Match:                 newLazyFunction(wasmRT, "cre2_match"),
		cre2NumCapturingGroups:    newLazyFunction(wasmRT, "cre2_num_capturing_groups"),
		cre2ErrorCode:             newLazyFunction(wasmRT, "cre2_error_code"),
		cre2ErrorArg:              newLazyFunction(wasmRT, "cre2_error_arg"),
		cre2NamedGroupsIterNew:    newLazyFunction(wasmRT, "cre2_named_groups_iter_new"),
		cre2NamedGroupsIterNext:   newLazyFunction(wasmRT, "cre2_named_groups_iter_next"),
		cre2NamedGroupsIterDelete: newLazyFunction(wasmRT, "cre2_named_groups_iter_delete"),
		cre2GlobalReplace:         newLazyFunction(wasmRT, "cre2_global_replace_re"),
		cre2OptNew:                newLazyFunction(wasmRT, "cre2_opt_new"),
		cre2OptDelete:             newLazyFunction(wasmRT, "cre2_opt_delete"),
		cre2OptSetLogErrors:       newLazyFunction(wasmRT, "cre2_opt_set_log_errors"),
		cre2OptSetLongestMatch:    newLazyFunction(wasmRT, "cre2_opt_set_longest_match"),
		cre2OptSetPosixSyntax:     newLazyFunction(wasmRT, "cre2_opt_set_posix_syntax"),
		cre2OptSetCaseSensitive:   newLazyFunction(wasmRT, "cre2_opt_set_case_sensitive"),
		cre2OptSetLatin1Encoding:  newLazyFunction(wasmRT, "cre2_opt_set_latin1_encoding"),

		malloc: newLazyFunction(wasmRT, "malloc"),
		free:   newLazyFunction(wasmRT, "free"),
	}

	return abi
}

func (abi *libre2ABI) startOperation(memorySize int) allocation {
	return abi.reserve(uint32(memorySize))
}

func (abi *libre2ABI) endOperation(a allocation) {
	a.free()
}

func newRE(abi *libre2ABI, pattern cString, opts CompileOptions) uintptr {
	ctx := context.Background()
	optPtr := uintptr(0)
	res, err := abi.cre2OptNew.Call0(ctx)
	if err != nil {
		panic(err)
	}
	optPtr = uintptr(res)
	defer func() {
		if _, err := abi.cre2OptDelete.Call1(ctx, uint64(optPtr)); err != nil {
			panic(err)
		}
	}()
	_, err = abi.cre2OptSetLogErrors.Call2(ctx, uint64(optPtr), 0)
	if err != nil {
		panic(err)
	}
	if opts.Longest {
		_, err = abi.cre2OptSetLongestMatch.Call2(ctx, uint64(optPtr), 1)
		if err != nil {
			panic(err)
		}
	}
	if opts.Posix {
		_, err = abi.cre2OptSetPosixSyntax.Call2(ctx, uint64(optPtr), 1)
		if err != nil {
			panic(err)
		}
	}
	if opts.CaseInsensitive {
		_, err = abi.cre2OptSetCaseSensitive.Call2(ctx, uint64(optPtr), 0)
		if err != nil {
			panic(err)
		}
	}
	if opts.Latin1 {
		_, err = abi.cre2OptSetLatin1Encoding.Call1(ctx, uint64(optPtr))
		if err != nil {
			panic(err)
		}
	}
	if res, err := abi.cre2New.Call3(ctx, uint64(pattern.ptr), uint64(pattern.length), uint64(optPtr)); err != nil {
		panic(err)
	} else {
		return uintptr(res)
	}
}

func reError(abi *libre2ABI, alloc *allocation, rePtr uintptr) (int, string) {
	ctx := context.Background()
	res, err := abi.cre2ErrorCode.Call1(ctx, uint64(rePtr))
	if err != nil {
		panic(err)
	}
	code := int(res)
	if code == 0 {
		return 0, ""
	}

	argPtr := alloc.newCStringArray(1)
	_, err = abi.cre2ErrorArg.Call2(ctx, uint64(rePtr), uint64(argPtr.ptr))
	if err != nil {
		panic(err)
	}
	sPtr := binary.LittleEndian.Uint32(alloc.read(argPtr.ptr, 4))
	sLen := binary.LittleEndian.Uint32(alloc.read(argPtr.ptr+4, 4))

	return code, string(alloc.read(uintptr(sPtr), int(sLen)))
}

func numCapturingGroups(abi *libre2ABI, rePtr uintptr) int {
	ctx := context.Background()
	res, err := abi.cre2NumCapturingGroups.Call1(ctx, uint64(rePtr))
	if err != nil {
		panic(err)
	}
	return int(res)
}

func deleteRE(abi *libre2ABI, rePtr uintptr) {
	//ctx := context.Background()
	//if _, err := abi.cre2Delete.Call1(ctx, uint64(rePtr)); err != nil {
	//	panic(err)
	//}
}

func release(re *Regexp) {
	deleteRE(re.abi, re.ptr)
}

func match(re *Regexp, s cString, matchesPtr uintptr, nMatches uint32) bool {
	ctx := context.Background()
	modH := getChildModule()
	defer putChildModule(modH)
	fun := modH.mod.ExportedFunction("cre2_match")
	res, err := fun.Call(ctx, uint64(re.ptr), uint64(s.ptr), uint64(s.length), 0, uint64(s.length), 0, uint64(matchesPtr), uint64(nMatches))
	if err != nil {
		panic(err)
	}
	return res[0] == 1
}

func matchFrom(re *Regexp, s cString, startPos int, matchesPtr uintptr, nMatches uint32) bool {
	ctx := context.Background()
	res, err := re.abi.cre2Match.Call8(ctx, uint64(re.ptr), uint64(s.ptr), uint64(s.length), uint64(startPos), uint64(s.length), 0, uint64(matchesPtr), uint64(nMatches))
	if err != nil {
		panic(err)
	}

	return res == 1
}

func readMatch(alloc *allocation, cs cString, matchPtr uintptr, dstCap []int) []int {
	matchBuf := alloc.read(matchPtr, 8)
	subStrPtr := uintptr(binary.LittleEndian.Uint32(matchBuf))
	sLen := uintptr(binary.LittleEndian.Uint32(matchBuf[4:]))
	sIdx := subStrPtr - cs.ptr

	return append(dstCap, int(sIdx), int(sIdx+sLen))
}

func readMatches(alloc *allocation, cs cString, matchesPtr uintptr, n int, deliver func([]int)) {
	var dstCap [2]int

	matchesBuf := alloc.read(matchesPtr, 8*n)
	for i := 0; i < n; i++ {
		subStrPtr := uintptr(binary.LittleEndian.Uint32(matchesBuf[8*i:]))
		if subStrPtr == 0 {
			deliver(append(dstCap[:0], -1, -1))
			continue
		}
		sLen := uintptr(binary.LittleEndian.Uint32(matchesBuf[8*i+4:]))
		sIdx := subStrPtr - cs.ptr
		deliver(append(dstCap[:0], int(sIdx), int(sIdx+sLen)))
	}
}

func namedGroupsIter(abi *libre2ABI, rePtr uintptr) uintptr {
	ctx := context.Background()

	res, err := abi.cre2NamedGroupsIterNew.Call1(ctx, uint64(rePtr))
	if err != nil {
		panic(err)
	}

	return uintptr(res)
}

func namedGroupsIterNext(abi *libre2ABI, iterPtr uintptr) (string, int, bool) {
	ctx := context.Background()

	// Not on the hot path so don't bother optimizing this yet.
	ptrs := malloc(abi, 8)
	defer free(abi, ptrs)
	namePtrPtr := ptrs
	indexPtr := namePtrPtr + 4

	res, err := abi.cre2NamedGroupsIterNext.Call3(ctx, uint64(iterPtr), uint64(namePtrPtr), uint64(indexPtr))
	if err != nil {
		panic(err)
	}

	if res == 0 {
		return "", 0, false
	}

	namePtr, ok := wasmMemory.ReadUint32Le(uint32(namePtrPtr))
	if !ok {
		panic(errFailedRead)
	}

	// C-string, read content until NULL.
	name := strings.Builder{}
	for {
		b, ok := wasmMemory.ReadByte(namePtr)
		if !ok {
			panic(errFailedRead)
		}
		if b == 0 {
			break
		}
		name.WriteByte(b)
		namePtr++
	}

	index, ok := wasmMemory.ReadUint32Le(uint32(indexPtr))
	if !ok {
		panic(errFailedRead)
	}

	return name.String(), int(index), true
}

func namedGroupsIterDelete(abi *libre2ABI, iterPtr uintptr) {
	ctx := context.Background()

	_, err := abi.cre2NamedGroupsIterDelete.Call1(ctx, uint64(iterPtr))
	if err != nil {
		panic(err)
	}
}

func globalReplace(re *Regexp, textAndTargetPtr uintptr, rewritePtr uintptr) ([]byte, bool) {
	ctx := context.Background()

	res, err := re.abi.cre2GlobalReplace.Call3(ctx, uint64(re.ptr), uint64(textAndTargetPtr), uint64(rewritePtr))
	if err != nil {
		panic(err)
	}

	if int64(res) == -1 {
		panic("out of memory")
	}

	if res == 0 {
		// No replacements
		return nil, false
	}

	strPtr, ok := wasmMemory.ReadUint32Le(uint32(textAndTargetPtr))
	if !ok {
		panic(errFailedRead)
	}
	// This was malloc'd by cre2, so free it
	defer free(re.abi, uintptr(strPtr))

	strLen, ok := wasmMemory.ReadUint32Le(uint32(textAndTargetPtr + 4))
	if !ok {
		panic(errFailedRead)
	}

	str, ok := wasmMemory.Read(strPtr, strLen)
	if !ok {
		panic(errFailedRead)
	}

	// Read returns a view, so make sure to copy it
	return append([]byte{}, str...), true
}

type cString struct {
	ptr    uintptr
	length int
}

type cStringArray struct {
	ptr uintptr
}

type pointer struct {
	ptr uintptr
}

func malloc(abi *libre2ABI, size uint32) uintptr {
	if res, err := abi.malloc.Call1(context.Background(), uint64(size)); err != nil {
		panic(err)
	} else {
		return uintptr(res)
	}
}

func free(abi *libre2ABI, ptr uintptr) {
	if _, err := abi.free.Call1(context.Background(), uint64(ptr)); err != nil {
		panic(err)
	}
}

type allocation struct {
	size    uint32
	bufPtr  uint32
	nextIdx uint32
	abi     *libre2ABI
}

func (abi *libre2ABI) reserve(size uint32) allocation {
	ptr := malloc(abi, size)
	return allocation{
		size:    size,
		bufPtr:  uint32(ptr),
		nextIdx: 0,
		abi:     abi,
	}
}

func (a *allocation) free() {
	free(a.abi, uintptr(a.bufPtr))
}

func (a *allocation) allocate(size uint32) uintptr {
	if a.nextIdx+size > a.size {
		panic("not enough reserved shared memory")
	}

	ptr := a.bufPtr + a.nextIdx
	a.nextIdx += size
	return uintptr(ptr)
}

func (a *allocation) read(ptr uintptr, size int) []byte {
	buf, ok := wasmMemory.Read(uint32(ptr), uint32(size))
	if !ok {
		panic(errFailedRead)
	}
	return buf
}

func (a *allocation) write(b []byte) uintptr {
	ptr := a.allocate(uint32(len(b)))
	wasmMemory.Write(uint32(ptr), b)
	return ptr
}

func (a *allocation) writeString(s string) uintptr {
	ptr := a.allocate(uint32(len(s)))
	wasmMemory.WriteString(uint32(ptr), s)
	return ptr
}

func (a *allocation) newCString(s string) cString {
	ptr := a.writeString(s)
	return cString{
		ptr:    ptr,
		length: len(s),
	}
}

func (a *allocation) newCStringFromBytes(s []byte) cString {
	ptr := a.write(s)
	return cString{
		ptr:    ptr,
		length: len(s),
	}
}

func (a *allocation) newCStringPtr(cs cString) pointer {
	ptr := a.allocate(8)
	if !wasmMemory.WriteUint32Le(uint32(ptr), uint32(cs.ptr)) {
		panic(errFailedWrite)
	}
	if !wasmMemory.WriteUint32Le(uint32(ptr+4), uint32(cs.length)) {
		panic(errFailedWrite)
	}
	return pointer{ptr: ptr}
}

func (a *allocation) newCStringArray(n int) cStringArray {
	ptr := a.allocate(uint32(n * 8))
	return cStringArray{ptr: ptr}
}

type lazyFunction struct {
	f    api.Function
	rt   wazero.Runtime
	name string
}

func newLazyFunction(rt wazero.Runtime, name string) lazyFunction {
	return lazyFunction{rt: rt, name: name}
}

func (f *lazyFunction) Call0(ctx context.Context) (uint64, error) {
	var callStack [1]uint64
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call1(ctx context.Context, arg1 uint64) (uint64, error) {
	var callStack [1]uint64
	callStack[0] = arg1
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call2(ctx context.Context, arg1 uint64, arg2 uint64) (uint64, error) {
	var callStack [2]uint64
	callStack[0] = arg1
	callStack[1] = arg2
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call3(ctx context.Context, arg1 uint64, arg2 uint64, arg3 uint64) (uint64, error) {
	var callStack [3]uint64
	callStack[0] = arg1
	callStack[1] = arg2
	callStack[2] = arg3
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call8(ctx context.Context, arg1 uint64, arg2 uint64, arg3 uint64, arg4 uint64, arg5 uint64, arg6 uint64, arg7 uint64, arg8 uint64) (uint64, error) {
	var callStack [8]uint64
	callStack[0] = arg1
	callStack[1] = arg2
	callStack[2] = arg3
	callStack[3] = arg4
	callStack[4] = arg5
	callStack[5] = arg6
	callStack[6] = arg7
	callStack[7] = arg8
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) callWithStack(ctx context.Context, callStack []uint64) (uint64, error) {
	modH := getChildModule()
	defer putChildModule(modH)
	fun := modH.mod.ExportedFunction(f.name)
	if err := fun.CallWithStack(ctx, callStack); err != nil {
		return 0, err
	}
	return callStack[0], nil
}
