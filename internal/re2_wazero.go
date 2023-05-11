//go:build !tinygo.wasm && !re2_cgo

package internal

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

var (
	errFailedWrite = errors.New("failed to read from wasm memory")
	errFailedRead  = errors.New("failed to read from wasm memory")
)

//go:embed wasm/libcre2.so
var libre2 []byte

var (
	wasmRT       wazero.Runtime
	wasmCompiled wazero.CompiledModule
)

type libre2ABI struct {
	cre2New                   api.Function
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
	cre2OptSetLongestMatch    lazyFunction
	cre2OptSetPosixSyntax     lazyFunction
	cre2OptSetCaseSensitive   lazyFunction
	cre2OptSetLatin1Encoding  lazyFunction

	malloc api.Function
	free   api.Function

	wasmMemory api.Memory

	mod api.Module
	mu  sync.Mutex
}

func init() {
	ctx := context.Background()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(api.CoreFeaturesV2|experimental.CoreFeaturesThreads))

	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	code, err := rt.CompileModule(ctx, libre2)
	if err != nil {
		panic(err)
	}
	wasmCompiled = code

	wasmRT = rt
}

func newABI() *libre2ABI {
	ctx := context.Background()
	mod, err := wasmRT.InstantiateModule(ctx, wasmCompiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		panic(err)
	}

	abi := &libre2ABI{
		cre2New:                   mod.ExportedFunction("cre2_new"),
		cre2Delete:                newLazyFunction(mod, "cre2_delete"),
		cre2Match:                 newLazyFunction(mod, "cre2_match"),
		cre2NumCapturingGroups:    newLazyFunction(mod, "cre2_num_capturing_groups"),
		cre2ErrorCode:             newLazyFunction(mod, "cre2_error_code"),
		cre2ErrorArg:              newLazyFunction(mod, "cre2_error_arg"),
		cre2NamedGroupsIterNew:    newLazyFunction(mod, "cre2_named_groups_iter_new"),
		cre2NamedGroupsIterNext:   newLazyFunction(mod, "cre2_named_groups_iter_next"),
		cre2NamedGroupsIterDelete: newLazyFunction(mod, "cre2_named_groups_iter_delete"),
		cre2GlobalReplace:         newLazyFunction(mod, "cre2_global_replace_re"),
		cre2OptNew:                newLazyFunction(mod, "cre2_opt_new"),
		cre2OptDelete:             newLazyFunction(mod, "cre2_opt_delete"),
		cre2OptSetLongestMatch:    newLazyFunction(mod, "cre2_opt_set_longest_match"),
		cre2OptSetPosixSyntax:     newLazyFunction(mod, "cre2_opt_set_posix_syntax"),
		cre2OptSetCaseSensitive:   newLazyFunction(mod, "cre2_opt_set_case_sensitive"),
		cre2OptSetLatin1Encoding:  newLazyFunction(mod, "cre2_opt_set_latin1_encoding"),

		malloc: mod.ExportedFunction("malloc"),
		free:   mod.ExportedFunction("free"),

		wasmMemory: mod.Memory(),
		mod:        mod,
	}

	return abi
}

func (abi *libre2ABI) startOperation(memorySize int) allocation {
	abi.mu.Lock()
	return abi.reserve(uint32(memorySize))
}

func (abi *libre2ABI) endOperation(a allocation) {
	a.free()
	abi.mu.Unlock()
}

func newRE(abi *libre2ABI, pattern cString, opts CompileOptions) uintptr {
	ctx := context.Background()
	optPtr := uintptr(0)
	if opts != (CompileOptions{}) {
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
	}
	var callStack [3]uint64
	callStack[0] = uint64(pattern.ptr)
	callStack[1] = uint64(pattern.length)
	callStack[2] = uint64(optPtr)
	if err := abi.cre2New.CallWithStack(ctx, callStack[:]); err != nil {
		panic(err)
	}
	return uintptr(callStack[0])
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
	ctx := context.Background()
	if _, err := abi.cre2Delete.Call1(ctx, uint64(rePtr)); err != nil {
		panic(err)
	}
}

func release(re *Regexp) {
	ctx := context.Background()
	deleteRE(re.abi, re.ptr)
	if err := re.abi.mod.Close(ctx); err != nil {
		fmt.Printf("error closing wazero module: %v", err)
	}
}

func match(re *Regexp, s cString, matchesPtr uintptr, nMatches uint32) bool {
	ctx := context.Background()
	res, err := re.abi.cre2Match.Call8(ctx, uint64(re.ptr), uint64(s.ptr), uint64(s.length), 0, uint64(s.length), 0, uint64(matchesPtr), uint64(nMatches))
	if err != nil {
		panic(err)
	}

	return res == 1
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

	namePtr, ok := abi.wasmMemory.ReadUint32Le(uint32(namePtrPtr))
	if !ok {
		panic(errFailedRead)
	}

	// C-string, read content until NULL.
	name := strings.Builder{}
	for {
		b, ok := abi.wasmMemory.ReadByte(namePtr)
		if !ok {
			panic(errFailedRead)
		}
		if b == 0 {
			break
		}
		name.WriteByte(b)
		namePtr++
	}

	index, ok := abi.wasmMemory.ReadUint32Le(uint32(indexPtr))
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

	strPtr, ok := re.abi.wasmMemory.ReadUint32Le(uint32(textAndTargetPtr))
	if !ok {
		panic(errFailedRead)
	}
	// This was malloc'd by cre2, so free it
	defer free(re.abi, uintptr(strPtr))

	strLen, ok := re.abi.wasmMemory.ReadUint32Le(uint32(textAndTargetPtr + 4))
	if !ok {
		panic(errFailedRead)
	}

	str, ok := re.abi.wasmMemory.Read(strPtr, strLen)
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
	var callStack [1]uint64
	callStack[0] = uint64(size)
	if err := abi.malloc.CallWithStack(context.Background(), callStack[:]); err != nil {
		panic(err)
	}
	return uintptr(callStack[0])
}

func free(abi *libre2ABI, ptr uintptr) {
	var callStack [1]uint64
	callStack[0] = uint64(ptr)
	if err := abi.free.CallWithStack(context.Background(), callStack[:]); err != nil {
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
	buf, ok := a.abi.wasmMemory.Read(uint32(ptr), uint32(size))
	if !ok {
		panic(errFailedRead)
	}
	return buf
}

func (a *allocation) write(b []byte) uintptr {
	ptr := a.allocate(uint32(len(b)))
	a.abi.wasmMemory.Write(uint32(ptr), b)
	return ptr
}

func (a *allocation) writeString(s string) uintptr {
	ptr := a.allocate(uint32(len(s)))
	a.abi.wasmMemory.WriteString(uint32(ptr), s)
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
	if !a.abi.wasmMemory.WriteUint32Le(uint32(ptr), uint32(cs.ptr)) {
		panic(errFailedWrite)
	}
	if !a.abi.wasmMemory.WriteUint32Le(uint32(ptr+4), uint32(cs.length)) {
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
	mod  api.Module
	name string
}

func newLazyFunction(mod api.Module, name string) lazyFunction {
	return lazyFunction{mod: mod, name: name}
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
	if f.f == nil {
		f.f = f.mod.ExportedFunction(f.name)
	}
	if err := f.f.CallWithStack(ctx, callStack); err != nil {
		return 0, err
	}
	return callStack[0], nil
}
