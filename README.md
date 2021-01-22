# Bypassing GLIBC 2.32's Safe-Linking Without Leaks into Code Execution: The House of Rust
The House of Rust is a heap exploitation technique that drops a shell against full PIE binaries that don't leak any addresses.

Check out the official post on [my website](https://c4ebt.github.io/2021/01/22/House-of-Rust.html).

### Breakdown
The House of Rust leverages a UAF to perform a number of well-known attacks that when combined result in the bypass of sigle list Safe-Linking without the need for leaks. The weak point it targets to effectively bypass Safe-Linking is the tcache stashing mechanism.
It utilizes some Heap Feng Shui, one Tcache Stashing Unlink+ attack, one Tcache Stashing Unlink attack, two largebin attacks and targets a stdout FILE stream FSOP attack.

### About Safe-Linking

From the original [CheckPoint Research post](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/) on the creation of Safe Linking:
> Safe-Linking makes use of randomness from the Address Space Layout Randomization (ASLR), now heavily deployed in most modern operating systems, to “sign” the list’s pointers. When combined with chunk alignment integrity checks, this new technique protects the pointers from hijacking attempts.

Safe-Linking XORs single list pointers with the 28 ASLR bits of the heap location of the pointer, making it impossible to corrupt successfully without a heap leak. Here's their code implementation:

```c
#define PROTECT_PTR(pos, ptr, type)  \
        ((type)((((size_t)pos) >> PAGE_SHIFT) ^ ((size_t)ptr)))
#define REVEAL_PTR(pos, ptr, type)   \
        PROTECT_PTR(pos, ptr, type)
```

Where `pos` is the position of the pointer in the heap, `PAGE_SHIFT` is 12 for 64-bit environments, and `ptr` is the original single list pointer.

### A Note to Safe-Linking Creators

Again, from the original [CheckPoint Research post](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/): 
> "Safe-Linking is not a magic bullet that will stop all exploit attempts against modern-day heap implementations. However, this is another step in the right direction. By forcing an attacker to have a pointer leak vulnerability before he can even start his heap-based exploit, we gradually raise the bar."

Mad respect for [Eyal Itkin](https://twitter.com/EyalItkin) and all the people that participated in the creation and implementation of the Single List Pointer Mangling. In my opinion, it is one of the most effective security mitigations that GLIBC has implemented lately. Although "forcing an attacker to have a pointer leak vulnerability before he can even start his heap-based exploit" is now proven to not be 100% accurate :D.

### About Other Techniques

At the time of publication I'm only aware of the existence of one other technique that claims to bypass Safe-Linking without leaks: The House of IO by [@Awarau1](https://twitter.com/Awarau1), which is described in [his blog](https://awaraucom.wordpress.com/). The House of IO targets the `tcache_perthread_struct` to gain control over unmangled `tcache_head` pointers. As mentioned in the blog post:

> The attack demands that the attacker has an underflow primitive, a use-after-free at a specific offset [+8] from the beginning of a struct, or a primitive which allows the attacker to place the tcache_perthread_struct on a tcache linked list. (...) Statistically speaking (at least from our experience), an underflow is by far less common than a plain overflow vulnerability. Additionally, to make the free() variants of this attack useful in the real world there are corner cases which need to be fulfilled – such as a UAF on a pointer field at an offset of 8 bytes within a struct, a badly ordered set of calls to free() on a struct, or through some other means by which to call  free() on a pointer to the  tcache_perthread_struct.

In my opinion (and it looks like the author of the blog post agrees), the primitives required for the House of IO are too demanding and unrealistic.

The House of Rust implementation I will present in this post also uses the `tcache_perthread_struct`, but simply because it is the weakest useful spot after the implementation of Safe-Linking and therefore results in a cleaner exploit. The HoR primitives perfectly allow for a direct attack into libc's stdout FILE stream without any need of touching the `tcache_perthread_struct`. Such an attack would require one extra Tcache Stashin Unlink+ attack and one extra largebin attack, so I opted for a `tcache_perthread_struct` approach. In that sense, the House of IO and the House of Rust are completely distinct, as their central targets are different mechanisms (`tcache_perthread_struct` and `tcache stashing mechanism` respectively).

Regardless of all this, kudos to @Awarau1 as well for developing a smart bypass very shortly after the new GLIBC version was released.

### Variations and Requirements

* The vanilla House of Rust technique requires good heap control where allocation pointers aren't nulled, leading to UAF scenarios. It requires around 65 allocations with sizes of up to 0x1b00. The stdout FSOP technique used in the vanilla version requires that the binary isn't line-buffered or fully-buffered.

* House of Corrosion variation: The "House of Crust". The House of Rust Safe-Linking bypass primitives can be leveraged into a way more complex variation leading to a House of Corrosion-like attack (hence the name "House of Crust"). This variation shares the same requirements as the vanilla HoR, except it needs a higher number of allocations and request sizes. The upside is that it doesn't require the target binary to not be line-buffered or fully-buffered, since it relies completely on relative overwrites and doesn't aim for the same stdout FSOP.

Both the House of Rust and the House of Crust require a 1/16 libc load-address entropy bruteforce.

### Previous Knowledge
As mentioned in the [breakdown](#breakdown), the House of Rust utilizes a number of other attacks to achieve its primitives. If you haven't heard of them before or want to know how they work in detail I encourage you to do so before reading this post to get a better understanding of everything. Detailed explanations about these attacks can be found in the following links:

* Tcache Stashing Unlink and Tcache Stashing Unlink+ attacks: https://qianfei11.github.io/2020/05/05/Tcache-Stashing-Unlink-Attack/
* Post 2.30 Largebin Attack: https://github.com/shellphish/how2heap/blob/master/glibc_2.31/large_bin_attack.c
* Stdout Leak-Oriented FSOP: https://vigneshsrao.github.io/posts/babytcache/
* House of Corrosion: https://github.com/CptGibbon/House-of-Corrosion/blob/master/README.md

## House of Rust

### Summary

The House of Rust can be divided into 5 steps that are executed in the following order:

- 1. Heap Feng Shui
- 2. Tcache Stashing Unlink+ (TSU+) and Largebin attack
- 3. Tcache Stashing Unlink (TSU) and Largebin attack
- 4. stdout FSOP leak
- 5. Final shell

### Stage 1: Heap Feng Shui

The sole purpose of this stage is to set up the heap for the other attacks. Thus, I will skip its explanation in this section and will reference it along the way. Keep in mind that it is very important to make all (or most) allocations in the beginning of the exploit, since allocating other chunks afterwards might get them served from unintended places such as forgotten smallbin chunks, or it could sort chunks from the unsortedbin into their respective bins when not intended.

### Stage 2: Tcache Stashing Unlink+ and Largebin Attack

Start by allocating 14 0x90-sized chunks (this size is not strictly the only option but it is the one I recommend). 7 of these chunks will be later freed into their tcachebin, allowing the next 7 chunks to go to the unsortedbin and be immediately sorted into the 0x90 smallbin. Additionally, 5 more allocations are required for a largebin attack (3 fencepost, 0x20-sized chunks, 2 large chunks).

Before allocating the first 14 chunks, allocate 2 large chunks such that the second qword of data of the second chunk overlaps the size field of the 14th 0x90-sized chunk. Free both of these chunks, consolidating them with the top chunk and "resetting" the heap. Repeat this step such that the second qword of the second chunk overlaps the bk_nextsize field of the first large chunk. Again, free both chunks to "reset" the heap. The purpose of this is to be able to edit the 0x90-sized chunk size and the large chunk bk_nextsize through the UAF bug. These chunks will be called write-after-free (WAF) chunks. After setting the position of these 2 WAF chunks properly, allocate a 0x30 sized chunk to later free it to write its address to the respective `tcache_head` in the `tcache_perthread_struct`.

Free the first 14 chunks ascending in an interwoven manner to avoid consolidation, filling up the tcachebin and putting 7 chunks in the unsortedbin. Allocate a large chunk to sort the unsorted chunks into the 0x90 smallbin. Edit the first WAF chunk to change the 14th chunk size so it chains with the first large chunk (0xb0 size if the fencepost chunk is 0x20 sized). Using the UAF, free the 14th chunk a second time, putting it into the 0xb0 tcachebin and writing the `tcache_key` to the chunk's second qword of data. Note that freeing this chunk into the tcachebin corrupts both the smallbin fd and bk. The `tcache_key` points to the beginnig of the `tcache_perthread_struct`. Edit chunk 14 to modify its bk's LSB, changing it to `"\x80"`. This points it higher up in the `tcache_perthread_struct`, more specifically to the 0x30 `&tcache_head - 0x18`. The presence of the 0x30 `tcache_head` is important to satisfy the need for a writable address in the TSU+ attack.

At this point, the 14th chunk is sorted into the smallbin and its bk is ready, pointing at the target location for the TSU+ attack. The issue is that the chunk's fd is completely corrupted, and executing the TSU+ attack now would cause a crash. This is why Tcache Stashing Unlink attacks were thought to be completely leak-dependant (until now ;) ).

The corrupt fd pointer can be "fixed" with a largebin attack. Aim a largebin attack at the first qword of the 14th chunk. To do this first free the first large chunk and sort it into its largebin by requesting a larger chunk and then freeing it. Overwrite the LSB of its bk_nextsize using the second WAF chunk. This ends up corrupting its fd_nextsize, but it doesn't matter. Make the bk_nextsize point to the address of the 14th chunk - 0x10. Then, free the second large chunk and request and free a larger chunk to sort it into the largebin. This results in the address of the second largebin being written to the 14th chunk's fd.

Edit the second largebin chunk and modify its bk's LSB to point it back to the 14th chunk. This closes the smallbin chain, and the TSU+ can be executed effectively without crashing or aborting.

Finally, trigger the TSU+ attack. To do this, empty up the tcachebin by allocating seven chunks from it, and then allocate one more chunk, which will be served from the smallbin, to start the stashing mechanism and execute the attack. This stage results in the 0x90 tcache head being pointed to the `0x080` offset from the `tcache_perthread_struct`. At this point, the next 0x90 sized request will be served at the `tcache_perthread_struct`.

### Stage 3: Tcache Stashing Unlink and Largebin Attack

As explained in the [first stage](#stage-1-heap-feng-shui), most of the allocations that are part of this stage actually have to be made at the beginning of the exploitation in the Heap Feng Shui stage, to avoid sorting or servicing chunks unintendedly.

The purpose of this stage is to write a libc value somewhere in the `tcache_perthread_struct` close to the final chunk allocated in the second stage. The pros of using a TSU attack instead of a TSU+ attack in this stage is that there is no need for a writable address to be present at the target+0x18.

Start by allocating 15 0xa0 sized chunks (again, this size is not strictly the only option but it is the one I recommend). In a similar fashion to the second stage, allocate 5 more chunks (3 0x20 sized, fencepost chunks and 2 large chunks). Note that the large chunks used in this stage must not belong to the same largebin as the ones used in the first stage. If the chunks used in the first stage belonged to the 0x400 largebin, use chunks that would go into the 0x480 largebin for this stage.

Similarly to the previous stage, allocate large chunks and free them to get WAF chunks to overwrite critical metadata later. The same metadata has to be overwritten: the 15th small chunk's size, and the first large chunk's bk_nextsize.

Again, like in the second stage, free the 15 chunks ascending in an interwoven manner to avoid consolidation, filling up the tcachebin and putting 7 chunks in the unsortedbin. Allocate a large chunk to sort the unsorted chunks into the 0xa0 smallbin. From here, this stage is exactly the same as the second stage, except the LSB that is overwritten over the `tcache_key` has to point up a little higher in the `tcache_perthread_struct` (there is some freedom here).

Executing the largebin attack and later the TSU attack achieves the goal of writing a libc address into the `tcache_perthread_struct` close to the final stage 2 chunk.

### Stage 4: stdout FSOP leak

The goal of this stage is to get a libc leak through a stdout FSOP technique.

Start by editing the chunk over the `tcache_perthread_struct` to overwrite the 2 LSBs of the libc value written on the third stage to point it to the stdout FILE structure. This requires guessing 4 bits of libc load-address entropy. On a successful guess, a chunk can be allocated from the appropiate tcachebin overlapping with `_IO_2_1_stdout_`. From here, the FSOP technique to get a leak is fairly simple, and is described thoroughly in [this post](https://vigneshsrao.github.io/posts/babytcache/) by sherl0ck.

To execute the technique, overwrite the `_IO_2_1_stdout_._flags` field with the value `0xfbad1800`. Null out the following 3 qwords, belonging to the fields `_IO_read_ptr`, `_IO_read_end` and `_IO_read_base`. Finally, null out the next qword's LSB belonging to `_IO_write_base`. This produces a huge information leak the next time there is stdout activity *through the file stream*. Keep in mind that all these fields have to be overwritten at the same time, else unexpected behavior may occur.

### Stage 5: Final Shell

Having a libc leak, the final stage of getting a shell is extremely simple.

Edit the chunk over the `tcache_perthread_struct` writing the value of `&__free_hook` over some `tcache_head`. Allocate a chunk from the appropiate tcachebin, and overwrite `__free_hook` with the address of `system`.

Finally, edit a chunk in the heap putting the string `"/bin/sh\x00"` in its first qword and then free it. This results in a call to `system("/bin/sh\x00")`, dropping a shell.

## House of Crust

The House of Crust utilizes the House of Rust primitives to leverage a House of Corrosion-like attack and drop a shell on completely leakless (yes, no stdout FSOP for leak) PIE binaries.

### Disclaimer

The House of Crust transplanting primitives can be achieved in a GLIBC build-independent basis, but the final FSOP attack heavily depends on the GLIBC build. As there is still no official or universally accepted GLIBC version 2.32 build for most systems, I had to build my own from source. I experimented and built 6 different libcs (from 2 different sources in 3 different systems), and the final FSOP attack I use in this demonstration was only possible on this build due to system characteristics and optimization flags. The final stage exploits a [bug](https://sourceware.org/pipermail/glibc-bugs/2020-April/047686.html) where the FILE stream vtables (more specifically the `__GI__IO_file_jumps`) are mapped into a writable memory segment. Additionally, one of the gadgets I use in the final stage to get a shell was only present in this build and could only be utilized in one way. I encourage the readers to attempt to leverage the House of Crust primitives to bypass libio vtable hardening [as described by the original House of Corrosion author](https://github.com/CptGibbon/House-of-Corrosion/blob/master/README.md#disabling-libio-vtable-protection).

### Difficulties and Differences

Building an application of the House of Corrosion for GLIBC 2.32 has a couple of extra difficulties and differences from the techniques described by the author in the original post for GLIBC 2.29.

In first place, doing a tcache dup to overwrite `global_max_fast` is no longer possible because of Safe-Linking. The House of Crust uses House of Rust primitives to achieve this.

In second place, tampering with House of Corrosion transplant data in-flight is no longer possible because the transplants correspond to fastbin allocations, which also are subject to Safe-Linking. This means that when the data we are transplanting is in the heap it is also subject to pointer mangling, making it impossible for us to tamper with it in-flight *in the heap*. To be able to modify it, we can use House of Rust primitives to get a chunk over libc and use it as a "tampering zone". This means that for each transplant with data tampering that we have to do, we can first transplant the data to this "tampering zone", then edit the chunk to tamper with the un-mangled data, and then transplant again from the "tampering zone" to the destination location.

Finally, and as mentioned in the disclaimer, FSOP attacks in this context are heavily GLIBC build dependent, so that is another difference from the original post to the House of Crust technique.

### Summary

The House of Crust starts off in a very similar way to the House of Rust. It then moves away from an impossible stdout FSOP libc leak (because of stdout line-buffering and full-buffering) and aims for a transplanting+tampering primitive just as the original House of Corrosion (but implemented in a different way). The following is a complete outline of the technique:

- 1. Heap Feng Shui
- 2. Tcache Stashing Unlink+ (TSU+) and Largebin Attack
- 3. Second Tcache Stashing Unlink+ (TSU+) and Largebin Attack
- 4. `global_max_fast` corruption into House of Corrosion-like transplanting+tampering primitive.
- 5. stderr FSOP attack.

### Stage 1: Heap Feng Shui

Just like with the House of Rust, this step will be explained along the way

### Stage 2: Tcache Stashing Unlink+ and Largebin Attack

This stage is exactly the same as in the House of Rust

### Stage 3: Second Tcache Stashing Unlink+ and Largebin Attack

This stage utilizes a TSU+ attack instead of the TSU attack used in the HoR stage 3. This is due to the need of 2 libc addresses being written to the `tcache_perthread_struct` instead of one (this will be explained later on). To execute a TSU+ instead of a TSU, the same as in the HoR stage 3 can be followed except a number of 14 chunks has to be allocated instead of 15. It is also needed to ensure that there is a writable address at `&target_address + 0x18` for the TSU+ attack to not crash. This can be achieved by allocating a chunk of a size such that when freed its `tcache_head` acts as this writable address. After triggering the stashing mechanism, the `tcache_head` of the utilized tcachebin points to the middle of the `tcache_perthread_struct`. Allocate a chunk to get a request pointer in this area.

The goal of this stage is to write 2 libc addresses to the `tcache_perthread_struct`. To do this, edit the first chunk in the `tcache_perthread_struct` to forge a fake large chunk size (0x500 recommended) for the chunk allocated from the previous step of this stage such that it chains with another (can be fake) chunk higher up in the heap (to pass unsortedbin nextsize checks). The large size has to be large enough to be sorted into an empty largebin (hence my 0x500 recomendation). Free the chunk, sending it to the unsortedbin, and request a larger allocation and then free it to sort the chunk into its largebin. This writes 2 libc addresses to the `tcache_perthread_struct` (largebin fd and bk).

This step has to be executed through largebin metadata because leaving the unsortedbin pointing to the `tcache_perthread_struct` would cause an `abort()` larter in the exploit.

### Stage 4: `global_max_fast` corruption into House of Corrosion-like transplanting+tampering primitive.

This stage starts having similarities with the House of Corrosion.

Start off by editing the chunk over the `tcache_perthread_struct` to overwrite the 2 LSBs of the large chunk's fd so it points to `global_max_fast-0x18`. This requires guessing 4 bits of libc load-address entropy. Next, allocate from the tcachebin corresponding to the `tcache_head` overwritten with the largebin fd. This gets a chunk at the `global_max_fast` variable. Immediately after getting this chunk, edit it to overwrite the `global_max_fast` variable with a large value (0x10000+ or whatever you want). The first goal of this stage is achieved at this point.

For the next step, start by editing the chunk over the `tcache_perthread_struct` to overwrite the 2 LSBs of the large chunk's bk so it points to a symbol-less, nulled out qword in libc (in my build `&main_arena+2256` works for this). Allocate from the appropiate tcachebin to get a chunk over this region. This chunk will be used as the "tampering zone" explained in the [difficulties and differences section](#difficulties-and-differences).

With `global_max_fast` corrupted and the tampering zone chunk set, the first step of this stage is completed. The next step is to get a transplanting primitive just like in the House of Corrosion. Because this step is exactly the same as the original post, I will not describe it in much detail. For more information about it, refer to the original [House of Corrosion post](https://github.com/CptGibbon/House-of-Corrosion/blob/master/README.md#stage-1-heap-feng-shui).

Allocate a **very large** chunk (*~0x4000 sized*) with data to act as "safe values" for fastbin allocations (in a `p64(0) + p64(0x21) + p64(0) + p64(0x31)` fashion). Allocate one last chunk (the size doesn't matter) after the largebin chunks used for the second largebin attack. This chunk will be the one used for the transplant primitive, and we will need to change its size. This requires setting up a fake chunk in the Heap Feng Shui stage so that it can be used to modify the chunk's size field.

This field will be edited multiple times, and the sizes written to it for transplants are calculated in the following way (from the original post [primitive one](https://github.com/CptGibbon/House-of-Corrosion/blob/master/README.md#primitive-one)):

> Use the formula: chunk size = (delta * 2) + 0x20 to calculate the size of a chunk needed to overwrite a target with its address when freed, where delta is the distance between the first fastbin and the target in bytes.

To execute a transplant, edit the size to the one corresponding to the destination address. In the case of the House of Crust, for each transplant the first destination address will be the tamper zone address. After editing the size, free the chunk. Then, edit the size again to the one corresponding to the source address. Once again, free the chunk. Edit the size back to the tamperzone size and request an allocation that would be serviced from the corresponding size. Finally, change the size back to the one corresponding to the source address and request an allocation that would be serviced from its corresponding size. This achieves a transplant from the source address into the tamperzone.

Now, the target data is in the tamperzone. Edit the tamperzone chunk to overwrite the wanted data. After editing, the tamperzone can be used as a source address to make one more, final transplant into the destination address following the same steps explained above. With a stable transplant+tamper primitive achieved, the stage 4 is completed.

### Stage 5: stderr FSOP attack

The final stage of the House of Crust requires executing 3 transplants and then triggering stderr activity. Keep in mind that this FSOP attack is GLIBC build dependent, and the gadgets present in my build might not be present in others.

The FSOP attack I will present overwrites an entry of the `__GI__IO_file_jumps` vtable, which shouldn't be mapped writable in an optimal situation but many libc builds present this bug.

The goal for this stage will be to execute the follwing `one_gadget` (keep in mind that this is GLIBC build-specific):

```
0xc8baa execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL
```

#### `__GI__IO_file_jumps.__overflow`

The first transplant will target the `__GI__IO_file_jumps.__overflow` field. The source for this transplant will be the `DW.ref.__gcc_personality_` symbol, that contains a libc code address. Tamper with its 2 LSBs to make it point to `&_nl_intern_locale_data+213`. As the 4th nibble of libc load address entropy was already guessed in the previous stage, this doesn't require any bruteforcing. In one of my GLIBC builds, the gadget at this address was the following:

```asm
	mov r12, r13
	movsxd rcx, DWORD PTR [rdx+r11*4]
	add rcx, rdx
	jmp rcx
```

When we trigger stderr activity in the final step, the `__overflow` entry of `_IO_2_1_stderr_.vtable` (which points to `__GI__IO_file_jumps`) will be called and the gadget will be executed. The other 2 transplants have the goal of satisfying conditions to make the use of this gadget profitable. In my experiments, the `__overflow` field was the only member of the vtable that provided sufficient conditions to make the gadget use profitable.

#### `_IO_helper_jumps`

This field ends up being `rdx` when the gadget gets executed. When `__overflow` is called, `r11` is 0, so what will end up being moved to rcx is whatever is in `[rdx]`. After that, `rdx` will be added to `rcx` and then the jump to `rcx` will be executed. How can we manage to control this jump? After the addition, we want to have `rcx` pointed to our `one_gadget`. We can control one of the operands in the addition (`rcx`), and the other one is a libc address `&_IO_helper_jumps`. This means that we can have a relative negative value in rcx such that when we add the value of the address of `_IO_helper_jumps` it points to the `one_gadget`. In my case, the value of `rdx` was at an offset of `0x1b98c0` from the libc base, so the negative relative value I had to use was `0xfffffffffff0f2ea` (`(0xfffffffffff0f2ea + 0x1b98c0) & 0xffffffffffffffff = 0xc8baa`). Transplant from whatever source and tamper the entire qword changing it to `0xfffffffffff0f2ea` and then move it to `&_IO_helper_jumps`.

#### `__GI__IO_file_jumps`

Finally, the `one_gadget` I chose has the following constraints that have to be satisfied:

```
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL
```

When `__overflow` is called, `r12` is a stack value and `r13` is `__GI__IO_file_jumps`. At the beginning of the gadget, a `mov r12, r13` is executed, setting both of them to `__GI__IO_file_jumps`. The gadget requires that both `r12` and `r13` are null, or that the contents of both of them are null. We will go for the latter. Transplant a null qword to `&__GI__IO_file_jumps` to complete all the necessary steps before triggering stderr activity and finishing the FSOP attack.

#### Triggering stderr activity

To finally trigger stderr activity and make the jump to our gadget the House of Crust goes for the same method as the House of Corrosion but implements it in a slightly different way.

Edit the chunk over the `global_max_fast` variable to change its value back to the normal `0x80`. In the Heap Feng Shui stage, allocate one last large chunk (its size has to belong to the same largebin as the chunks used in the third stage of the House of Crust) right before the chunk used for the transplants, and arrange a fake chunk that will be used to tamper with the size field of the first largebin chunk used for the second largebin attack in the third stage of the House of Crust. Edit the fake chunk to set the `NON_MAIN_ARENA` bit in the largebin chunk size field. Finally, free the last large chunk, sending it into the unsortedbin, and make a larger allocation to try to sort it into its largebin. When trying to sort a chunk into a largebin with a chunk that has the `NON_MAIN_ARENA` bit set, malloc triggers stderr activity right before attempting to abort. This results in `__GI__IO_file_jumps.__overflow` being called, which in turn jumps to our gadget consecuentially calling the `one_gadget` and dropping a shell.

## Final Thoughts

I really enjoyed all the learning, practicing and researching I went through while building the House of Rust and House of Crust techniques. I would love to discuss these techniques further and will welcome all feedback, so feel free to contact me through Discord `c4e#8859` or Twitter `@c4ebt`.

Special thanks to my friend and teammate [FizzBuzz101](https://www.willsroot.io/) for proofreading this post and helping me get here.
