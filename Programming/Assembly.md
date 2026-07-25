Assembly is a low-level language that maps almost directly to a CPU's machine instructions, using human-readable mnemonics (like `mov`, `push`, `call`) instead of raw binary opcodes. It give precise, hardware-level control over registers, memory, and execution flow.

> This will focus mainly on the Intel x86 64-bit assembly language (also known as x86_64 and AMD64), using Intel syntax. Might expand later...
# Architecture
Most modern computers are built on Von Neumann Architecture. Essentially, CPU, memory, and I/O.
## Speed
Speed is largely determined by distance from the CPU and clock speed. Further distance = slower.

| Component   | Speed                             | Size                |
| ----------- | --------------------------------- | ------------------- |
| `Registers` | Fastest                           | Bytes               |
| `L1 Cache`  | Fastest, other than Registers     | Kilobytes           |
| `L2 Cache`  | Very fast                         | Megabytes           |
| `L3 Cache`  | Fast, but slower than the above   | Megabytes           |
| `RAM`       | Much slower than all of the above | Gigabytes-Terabytes |
| `Storage`   | Slowest                           | Terabytes and more  |
## Memory
Cache - Inside CPU, faster than RAM, limited in size
RAM - larger than cache memory, slower

RAM has four main segments:

|Segment|Description|
|---|---|
|`Stack`|Has a Last-in First-out (LIFO) design and is fixed in size. Data in it can only be accessed in a specific order by push-ing and pop-ing data.|
|`Heap`|Has a hierarchical design and is therefore much larger and more versatile in storing data, as data can be stored and retrieved in any order. However, this makes the heap slower than the Stack.|
|`Data`|Has two parts: `Data`, which is used to hold variables, and `.bss`, which is used to hold unassigned variables (i.e., buffer memory for later allocation).|
|`Text`|Main assembly instructions are loaded into this segment to be fetched and executed by the CPU.|
This segmentation applies to RAM as well as each application (each app is allocated virtual memory when run).
## CPU
The Central Processing Unit (CPU) is the main processing unit of a computer.
	`Control Unit (CU)` : in charge of moving data
	`Arithmetic/Logic Unit (ALU)` : performs various arithmetic as requested by program through assembly instructions

The manner in which a CPU processes its instructions depends on its `Instruction Set Architecture (ISA)`. RISC, CISC, etc...

Clock speed : 
	Every tick of the clock runs a clock cycle that processes a basic instruction.
	`Hertz` : The frequency the cycles occur in cycles per second.
	Multi-core processor = multiple cycles at the same time.

`Instruction Cycle`: The cycle the CPU takes to process a single machine instruction.

| **Instruction** | **Description**                                                                                                                           |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `1. Fetch`      | Takes the next instruction's address from the `Instruction Address Register` (IAR), which tells it where the next instruction is located. |
| `2. Decode`     | Takes the instruction from the IAR, and decodes it from binary to see what is required to be executed.                                    |
| `3. Execute`    | Fetch instruction operands from register/memory, and process the instruction in the `ALU` or `CU`.                                        |
| `4. Store`      | Store the new value in the destination operand.                                                                                           |
> All of the stages in the instruction cycle are carried out by the Control Unit, except when arithmetic instructions need to be executed "add, sub, ..etc", which are executed by the ALU.

Each Instruction Cycle takes multiple clock cycles to finish, then increments to the next instruction.
### Processor Specific
It is important to understand that each processor has its own set of instructions and corresponding machine code.

Example:
	64-bit x86 architecture
		`4883C001` as `add rax, 1`
	ARM processor
		`4883C001` as `biceq r8, r0, r8, asr #6`

Why?
	Instruction Set Architectures (ISA) differ.

Also, a single ISA may have several syntax interpretations for the same assembly code. 
	`add rax, 1` - Intel syntax
	`addb $0x1,%rax` - AT&T syntax.

> So, each processor type has its Instruction Set Architectures, and each architecture can be further represented in several syntax formats

## Instruction Set Architectures
An `Instruction Set Architecture` (`ISA`) specifies the syntax and semantics of the assembly language on each architecture. Consists of the following:

|Component|Description|Example|
|---|---|---|
|`Instructions`|The instruction to be processed in the `opcode operand_list` format. There are usually 1,2, or 3 comma-separated operands.|`add rax, 1`, `mov rsp, rax`, `push rax`|
|`Registers`|Used to store operands, addresses, or instructions temporarily.|`rax`, `rsp`, `rip`|
|`Memory Addresses`|The address in which data or instructions are stored. May point to memory or registers.|`0xffffffffaa8a25ff`, `0x44d0`, `$rax`|
|`Data Types`|The type of stored data.|`byte`, `word`, `double word`|
`Complex Instruction Set Computer` (`CISC`) - Used in `Intel` and `AMD` processors in most computers and servers.
`Reduced Instruction Set Computer` (`RISC`) - Used in `ARM` and `Apple` processors, in most smartphones, and some modern laptops.

| Area                             | CISC                                                        | RISC                                                |
| -------------------------------- | ----------------------------------------------------------- | --------------------------------------------------- |
| `Complexity`                     | Favors complex instructions                                 | Favors simple instructions                          |
| `Length of instructions`         | Longer instructions - Variable length 'multiples of 8-bits' | Shorter instructions - Fixed length '32-bit/64-bit' |
| `Total instructions per program` | Fewer total instructions - Shorter code                     | More total instructions - Longer code               |
| `Optimization`                   | Relies on hardware optimization (in CPU)                    | Relies on software optimization (in Assembly)       |
| `Instruction Execution Time`     | Variable - Multiple clock cycles                            | Fixed - One clock cycle                             |
| `Instructions supported by CPU`  | Many instructions (~1500)                                   | Fewer instructions (~200)                           |
| `Power Consumption`              | High                                                        | Very low                                            |
| `Examples`                       | Intel, AMD                                                  | ARM, Apple                                          |
## Registers, Addresses, and Data Types
### Registers
Each CPU core has a set of registers. Fastest component, but limited in size -- They can only hold a few bytes of data at a time.

Many registers in x86. Here are the basics:

|**Data Registers**|**Pointer Registers**|
|---|---|
|`rax`|`rbp`|
|`rbx`|`rsp`|
|`rcx`|`rip`|
|`rdx`||
|`r8`||
|`r9`||
|`r10`|
`Data Registers` : storing instructions / syscall arguments.
`Pointer Registers` : store specific important address pointers.
### Sub-Registers
Each `64-bit` register can be further divided into smaller sub-registers containing lower bits, like 8-bit, 2 bytes, 4 bytes, etc...

Sub-registers can be accessed as:

| Size in bits | Size in bytes | Name                                   | Example |
| ------------ | ------------- | -------------------------------------- | ------- |
| `16-bit`     | `2 bytes`     | the base name                          | `ax`    |
| `8-bit`      | `1 bytes`     | base name and/or ends with `l`         | `al`    |
| `32-bit`     | `4 bytes`     | base name + starts with the `e` prefix | `eax`   |
| `64-bit`     | `8 bytes`     | base name + starts with the `r` prefix | `rax`   |
Another example set could be bx, bl, ebx, rbx.
### Memory Addresses
The following are names of sub-registers in x86_64 architecture.

|Description|64-bit Register|32-bit Register|16-bit Register|8-bit Register|
|---|---|---|---|---|
|**Data/Arguments Registers**|||||
|Syscall Number/Return value|`rax`|`eax`|`ax`|`al`|
|Callee Saved|`rbx`|`ebx`|`bx`|`bl`|
|1st arg - Destination operand|`rdi`|`edi`|`di`|`dil`|
|2nd arg - Source operand|`rsi`|`esi`|`si`|`sil`|
|3rd arg|`rdx`|`edx`|`dx`|`dl`|
|4th arg - Loop counter|`rcx`|`ecx`|`cx`|`cl`|
|5th arg|`r8`|`r8d`|`r8w`|`r8b`|
|6th arg|`r9`|`r9d`|`r9w`|`r9b`|
|**Pointer Registers**|||||
|Base Stack Pointer|`rbp`|`ebp`|`bp`|`bpl`|
|Current/Top Stack Pointer|`rsp`|`esp`|`sp`|`spl`|
|Instruction Pointer 'call only'|`rip`|`eip`|`ip`|`ipl`|
### Address Endianness
Address endianness is the order of its bytes in which they are stored and retrieved.

`Little-Endian` : little-end byte of the address is filled/retrieved first right-to-left.
`Big-Endian` : Big byte is filled/retrieved first left-to-right.

Example:
	`0x0011223344556677` needs to be stored in memory.
	Little-endian, it looks like `0x7766554433221100` when stored. When retrieved it would return the original value.

> We will use little-endian byte order going forward. IE: Our bytes will be stored right-to-left.
### Data Types
The following are the most common data types we will be using with instructions:

|Component|Length|Example|
|---|---|---|
|`byte`|8 bits|`0xab`|
|`word`|16 bits - 2 bytes|`0xabcd`|
|`double word (dword)`|32 bits - 4 bytes|`0xabcdef12`|
|`quad word (qword)`|64 bits - 8 bytes|`0xabcdef1234567890`|
Instructions and data types or vars must be of the same size. The following table shows appropriate data type for each sub-register.

|Sub-register|Data Type|
|---|---|
|`al`|`byte`|
|`ax`|`word`|
|`eax`|`dword`|
|`rax`|`qword`|

# Assembling & Debugging
## Assembly File Structure

# Basic Instructions
# Control Instructions
# Functions
# Shellcoding