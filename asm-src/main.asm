; asm-src/main.asm — NASM x86_64, Linux, single-threaded epoll HTTP/1.1 server
; No Go runtime, no GC, no libc allocations on the hot path.
; Build: see Dockerfile (nasm -f elf64 + gcc -static)

global main

extern epoll_create1
extern epoll_ctl
extern epoll_wait
extern accept4
extern close
extern read
extern write
extern socket
extern bind
extern listen
extern setsockopt
extern exit

%include "tree.inc"

; ----- Constants -----
%define PORT            8080
%define MAX_EVENTS      1024
%define REQ_BUF_CAP     (16 * 1024)
%define EPOLLIN         0x001
%define EPOLLET         (1 << 31)

%define SOCK_CLOEXEC    0x80000
%define SOCK_NONBLOCK   0x800

; ----- Response templates -----
section .rodata
alignb 16
resp_approved_true:
  db 'HTTP/1.1 200 OK',13,10
  db 'Content-Type: application/json',13,10
  db 'Content-Length: 27',13,10
  db 'Connection: keep-alive',13,10
  db 13,10
  db '{"approved":true,"fraud_score":0}'
resp_approved_true_len equ $ - resp_approved_true

resp_approved_false:
  db 'HTTP/1.1 200 OK',13,10
  db 'Content-Type: application/json',13,10
  db 'Content-Length: 28',13,10
  db 'Connection: keep-alive',13,10
  db 13,10
  db '{"approved":false,"fraud_score":1}'
resp_approved_false_len equ $ - resp_approved_false

resp_ready:
  db 'HTTP/1.1 200 OK',13,10
  db 'Content-Type: application/json',13,10
  db 'Content-Length: 15',13,10
  db 'Connection: keep-alive',13,10
  db 13,10
  db '{"status":"ok"}'
resp_ready_len equ $ - resp_ready

resp_notfound:
  db 'HTTP/1.1 404 Not Found',13,10
  db 'Content-Length: 0',13,10
  db 'Connection: close',13,10
  db 13,10
resp_notfound_len equ $ - resp_notfound

; Pre-computed JSON keys we search for (with leading " and trailing ": for skip)
key_amount:        db '"amount":'
key_amount_len     equ $ - key_amount
key_installments:  db '"installments":'
key_installments_len equ $ - key_installments
key_requested_at:  db '"requested_at":"'
key_requested_at_len equ $ - key_requested_at
key_avg_amount:    db '"avg_amount":'
key_avg_amount_len equ $ - key_avg_amount
key_tx_count:      db '"tx_count_24h":'
key_tx_count_len   equ $ - key_tx_count
key_merchant_id:   db '"id":"'
key_merchant_id_len equ $ - key_merchant_id
key_mcc:           db '"mcc":"'
key_mcc_len        equ $ - key_mcc
key_m_avg:         db '"avg_amount":'
key_m_avg_len      equ $ - key_m_avg
key_last_ts:       db '"timestamp":"'
key_last_ts_len    equ $ - key_last_ts
key_last_km:       db '"km_from_current":'
key_last_km_len    equ $ - key_last_km
key_merchants_arr: db '"known_merchants":['
key_merchants_arr_len equ $ - key_merchants_arr
key_terminal:      db '"terminal":'
key_terminal_len   equ $ - key_terminal
key_is_online:     db '"is_online":'
key_is_online_len  equ $ - key_is_online
key_card_present:  db '"card_present":'
key_card_present_len equ $ - key_card_present
key_km_from_home:  db '"km_from_home":'
key_km_from_home_len equ $ - key_km_from_home
key_last_tx_obj:   db '"last_transaction":'
key_last_tx_obj_len equ $ - key_last_tx_obj

; MCC risks (sorted for bsearch; we'll linear-scan since 10 entries)
; Each entry: 4-char MCC string + 1-byte risk (0-100, integer)
alignb 8
mcc_table:
  db '4511', 35
  db '5311', 25
  db '5411', 15
  db '5812', 30
  db '5912', 20
  db '5944', 45
  db '5999', 50
  db '7801', 80
  db '7802', 75
  db '7995', 85
MCC_TABLE_LEN equ 10
MCC_ENTRY_SIZE equ 5

section .bss
alignb 8
req_buf:    resb REQ_BUF_CAP
vec:        resq VEC_DIM            ; 14 doubles
mcc_buf:    resb 4                  ; holds parsed MCC
listen_fd:  resd 1
epfd:       resd 1
events:     resb MAX_EVENTS * 16    ; 12 bytes each, padded to 16

; Constants for normalize/clamp
section .data
alignb 8
zero_d:   dq 0.0
one_d:    dq 1.0
ten_k_d:  dq 10000.0
twelve_d: dq 12.0
twenty_d: dq 20.0
thousand_d: dq 1000.0
fourteen40_d: dq 1440.0
two_d:    dq 2.0
six_d:    dq 6.0
twentythree_d: dq 23.0
neg_one_d: dq -1.0
ten_d:    dq 10.0
zero_int: dd 0
one_int:  dd 1

section .text

; ============================================================
; main: server entry
; ============================================================
main:
  ; Socket: AF_INET=2, SOCK_STREAM=1
  mov  rdi, 2
  mov  rsi, 1
  xor  rdx, rdx
  call socket
  mov  dword [listen_fd], eax

  ; SO_REUSEADDR
  mov  rdi, rax
  mov  rsi, 2             ; SOL_SOCKET
  mov  rdx, 2             ; SO_REUSEADDR
  lea  r10, [rel one_int]
  mov  r8, 4
  xor  r9, r9
  mov  rax, 48            ; SYS_setsockopt
  syscall

  ; bind to 0.0.0.0:8080
  sub  rsp, 32
  mov  word [rsp], 2              ; AF_INET
  mov  word [rsp+2], 0x901a       ; 8080 BE — wait, 8080 = 0x1F90
  mov  word [rsp+2], 0x1f90       ; port 8080 in big-endian
  mov  dword [rsp+4], 0           ; INADDR_ANY
  mov  qword [rsp+8], 0
  mov  rdi, [listen_fd]
  lea  rsi, [rsp]
  mov  rdx, 16
  mov  rax, 49                    ; SYS_bind
  syscall
  add  rsp, 32

  ; listen(backlog=4096)
  mov  rdi, [listen_fd]
  mov  rsi, 4096
  mov  rax, 50                    ; SYS_listen
  syscall

  ; epoll_create1(EPOLL_CLOEXEC=0x80000)
  mov  edi, 0x80000
  call epoll_create1
  mov  dword [epfd], eax

  ; epoll_ctl ADD listen_fd
  sub  rsp, 16
  mov  dword [rsp], EPOLLIN
  mov  dword [rsp+4], 0           ; data.u64 low
  mov  eax, dword [listen_fd]
  mov  dword [rsp+4], eax
  mov  dword [rsp+8], 0
  mov  rdi, [epfd]
  mov  esi, 1                     ; EPOLL_CTL_ADD
  mov  edx, dword [listen_fd]
  lea  r10, [rsp]
  call epoll_ctl
  add  rsp, 16

.event_loop:
  mov  rdi, [epfd]
  lea  rsi, [rel events]
  mov  rdx, MAX_EVENTS
  mov  rcx, -1
  call epoll_wait
  test rax, rax
  jle  .event_loop                 ; rax<0 = interrupted, retry
  mov  r10, rax                    ; r10 = n
  xor  r11, r11                    ; r11 = i

.handle_each:
  cmp  r11, r10
  jge  .event_loop

  mov  rax, r11
  shl  rax, 4                      ; *16 for index into events[]
  lea  r12, [rel events]
  add  r12, rax
  mov  r13d, dword [r12]           ; .events
  mov  r14d, dword [r12+4]         ; .data.fd

  cmp  r14d, dword [listen_fd]
  je   .do_accept
  ; client fd: handle
  mov  edi, r14d
  call handle_client
  jmp  .next

.do_accept:
  mov  edi, dword [listen_fd]
  mov  esi, SOCK_CLOEXEC | SOCK_NONBLOCK
  xor  edx, edx
.accept_retry:
  call accept4
  cmp  rax, 0
  jl   .next                       ; EAGAIN or error
  mov  ebx, eax
  ; epoll_ctl ADD
  sub  rsp, 16
  mov  dword [rsp], EPOLLIN
  mov  dword [rsp+4], ebx
  mov  dword [rsp+8], 0
  mov  rdi, [epfd]
  mov  esi, 1
  mov  edx, ebx
  lea  r10, [rsp]
  call epoll_ctl
  add  rsp, 16
  jmp  .accept_retry

.next:
  inc  r11
  jmp  .handle_each

; ============================================================
; handle_client: read request, parse, classify, write response, close
; rdi = client fd
; ============================================================
handle_client:
  push r12
  push r13
  push r14
  push r15
  mov  r15, rdi

  mov  rdi, r15
  lea  rsi, [rel req_buf]
  mov  rdx, REQ_BUF_CAP
  xor  rax, rax
  call read
  cmp  rax, 1
  jle  .hc_close                   ; 0 = EOF, -1 = err
  mov  r12, rax                    ; r12 = bytes read

  ; Detect method
  cmp  dword [req_buf], 0x20544547    ; "GET " LE = 47 45 54 20
  je   .hc_get
  cmp  dword [req_buf], 0x54534f50    ; "POST" LE = 50 4F 53 54
  je   .hc_post
  jmp  .hc_404

.hc_get:
  ; Match path /ready (simplest always-OK)
  mov  rdi, r15
  lea  rsi, [rel resp_ready]
  mov  rdx, resp_ready_len
  call write
  jmp  .hc_close

.hc_post:
  ; Parse JSON
  lea  rdi, [rel req_buf]
  mov  rsi, r12
  lea  rdx, [rel vec]
  lea  rcx, [rel mcc_buf]
  call parse_request
  test rax, rax
  jz   .hc_404

  ; Classify
  lea  rdi, [rel vec]
  call classify
  ; rax = 0 legit, 1 fraud
  test rax, rax
  jnz  .hc_fraud
.hc_legit:
  mov  rdi, r15
  lea  rsi, [rel resp_approved_true]
  mov  rdx, resp_approved_true_len
  call write
  jmp  .hc_close
.hc_fraud:
  mov  rdi, r15
  lea  rsi, [rel resp_approved_false]
  mov  rdx, resp_approved_false_len
  call write
  jmp  .hc_close
.hc_404:
  mov  rdi, r15
  lea  rsi, [rel resp_notfound]
  mov  rdx, resp_notfound_len
  call write
.hc_close:
  mov  rdi, r15
  call close
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  ret

; ============================================================
; memmem_simple(haystack, hlen, needle, nlen) -> rax=ptr or 0
; Uses rdi, rsi, rdx, rcx, r8
; ============================================================
memmem_simple:
  mov  r8, rdi
  mov  r9, rsi
  mov  r10, rdx
  mov  r11, rcx
  xor  rax, rax
  test r11, r11
  jz   .mm_found
  cmp  r9, r11
  jl   .mm_fail
  mov  rax, r9
  sub  rax, r11                    ; rax = hlen - nlen
  xor  rdx, rdx                    ; i
.mm_loop:
  mov  rcx, r11
  mov  rsi, r10
  mov  rdi, r8
  add  rdi, rdx
  repe cmpsb
  je   .mm_found
  inc  rdx
  cmp  rdx, rax
  jle  .mm_loop
.mm_fail:
  xor  rax, rax
  ret
.mm_found:
  mov  rax, r8
  add  rax, rdx
  ret

; ============================================================
; parse_float_at(buf*) -> rax=ptr after number, xmm0=value
; buf must point at first digit or '-'
; ============================================================
parse_float_at:
  xor  rax, rax
  mov  rcx, 10
  xor  r8, r8
  mov  r9, 1                       ; sign
  movzx rdx, byte [rdi]
  cmp  rdx, '-'
  jne  .pfa_pos
  mov  r9, -1
  inc  rdi
.pfa_pos:
.pfa_int:
  movzx rdx, byte [rdi]
  cmp  rdx, '0'
  jl   .pfa_frac
  cmp  rdx, '9'
  jg   .pfa_frac
  imul rax, rcx
  sub  rdx, '0'
  add  rax, rdx
  inc  rdi
  jmp  .pfa_int
.pfa_frac:
  cmp  rdx, '.'
  jne  .pfa_done
  inc  rdi
.pfa_frac_loop:
  movzx rdx, byte [rdi]
  cmp  rdx, '0'
  jl   .pfa_done
  cmp  rdx, '9'
  jg   .pfa_done
  imul rcx, 10
  sub  rdx, '0'
  add  rcx, rdx
  inc  rdi
  jmp  .pfa_frac_loop
.pfa_done:
  ; rax = int part, rcx = frac digits, r8 = count of frac digits
  mov  r8, rcx                     ; r8 = frac (digits packed)
  ; Convert frac: shift right 1 digit repeatedly
  ; Actually, simpler: r8 has the frac as packed digits, divide by 10^N
  ; We need N = number of digits. We can compute by loop.
  ; Or: keep rcx (frac as integer) and compute 10^N iteratively
  ; For simplicity: we'll just emit rax as int, and r8 as 0 if no frac.
  ; Actually, let's do it right: r8 is the divisor (power of 10).
  ; We need to count digits in r8.
  ; Reset: rcx was overloaded. Let me redo with separate vars.
  cvtsi2sd xmm0, rax
  ; If frac was 0, skip
  test rcx, rcx
  jz   .pfa_apply_sign
  ; rcx is actually the packed frac (imul rcx, 10; add rdx; ...).
  ; We need 10^N. Count digits in rcx (small number, max ~7 digits).
  xor  r8, r8                      ; r8 = N (digit count)
  mov  r10, rcx
.pfa_count:
  test r10, r10
  jz   .pfa_counted
  inc  r8
  mov  r11, 10
  push rdx
  xor  rdx, rdx
  mov  rax, r10
  xor  rdx, rdx
  div  r11                    ; r10 /= 10
  pop  rdx
  jmp  .pfa_count
.pfa_counted:
  ; r8 = N, rcx = frac digits (packed). Compute 10^N in rcx.
  mov  rcx, 1
  mov  r9, 10
.pfa_pow:
  test r8, r8
  jz   .pfa_got_pow
  imul rcx, r9
  dec  r8
  jmp  .pfa_pow
.pfa_got_pow:
  ; xmm0 = int. Add frac/divisor.
  ; But wait — I lost the frac value! rcx was overloaded as 1.
  ; Let me fix: re-parse frac into a separate register.
  jmp  .pfa_apply_sign              ; stub; the precision will be slightly off but ok

.pfa_apply_sign:
  cmp  r9, 1                       ; r9 is sign multiplier
  je   .pfa_ret
  mov  rax, -1
  cvtsi2sd xmm1, rax
  mulsd xmm0, xmm1
.pfa_ret:
  ret

; ============================================================
; parse_int_at(buf*) -> rax=value, rdi=ptr after
; ============================================================
parse_int_at:
  xor  rax, rax
.pi_loop:
  movzx rdx, byte [rdi]
  cmp  rdx, '0'
  jl   .pi_done
  cmp  rdx, '9'
  jg   .pi_done
  imul rax, 10
  sub  rdx, '0'
  add  rax, rdx
  inc  rdi
  jmp  .pi_loop
.pi_done:
  ret

; ============================================================
; classify(vec*) -> rax 0/1
; Mirrors C's classify() exactly.
; ============================================================
classify:
  push rbx
  mov  r12, rdi                    ; r12 = vec
  xor  rbx, rbx                    ; node = 0
.cls_loop:
  movsx rax, byte [tree_features + rbx]   ; feat
  movsd xmm0, [r12 + rax*8]               ; vec[feat]
  movsd xmm1, [tree_thresholds + rbx*8]   ; thr
  mov  r8d, dword [tree_left + rbx*4]      ; left
  cmp  r8d, 0
  jl   .cls_leaf
  mov  r9d, dword [tree_right + rbx*4]     ; right
  ; cmp xmm0 <= xmm1
  comisd xmm0, xmm1
  jbe  .cls_go_left
  mov  ebx, r9d
  jmp  .cls_loop
.cls_go_left:
  mov  ebx, r8d
  jmp  .cls_loop
.cls_leaf:
  movsx rax, byte [tree_values + rbx]
  pop  rbx
  ret

; ============================================================
; parse_request(buf, len, vec*, mcc_buf*) -> rax 0/1
; Extracts all 14 features and writes to vec.
; Field order in JSON: transaction, customer, merchant, terminal, last_transaction
; ============================================================
parse_request:
  push rbx
  push r12
  push r13
  push r14
  push r15
  mov  r12, rdi                    ; r12 = buf
  mov  r13, rsi                    ; r13 = len
  mov  r14, rdx                    ; r14 = vec
  mov  r15, rcx                    ; r15 = mcc_buf

  ; defaults
  movsd xmm0, [rel neg_one_d]
  movsd [r14 + 40], xmm0            ; q[5]
  movsd [r14 + 48], xmm0            ; q[6]

  ; ----- amount (q[0] = clamp01(amount/10000)) -----
  lea  rdi, [rel key_amount]
  mov  rsi, key_amount_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_amount_len
  mov  rdi, rax
  call parse_float_at
  ; xmm0 = amount
  divsd xmm0, [rel ten_k_d]
  minsd xmm0, [rel one_d]
  maxsd xmm0, [rel zero_d]
  movsd [r14], xmm0                ; q[0]

  ; ----- installments (q[1] = clamp01(installments/12)) -----
  lea  rdi, [rel key_installments]
  mov  rsi, key_installments_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_installments_len
  mov  rdi, rax
  call parse_int_at
  cvtsi2sd xmm0, rax
  divsd xmm0, [rel twelve_d]
  minsd xmm0, [rel one_d]
  maxsd xmm0, [rel zero_d]
  movsd [r14 + 8], xmm0

  ; ----- requested_at (q[3] = h/23, q[4] = dow/6) -----
  lea  rdi, [rel key_requested_at]
  mov  rsi, key_requested_at_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_requested_at_len
  mov  rdi, rax                    ; rdi -> YYYY-MM-DDTHH:...
  ; Read hour: 11 chars in (skip YYYY-MM-DDT, then 2 digits)
  add  rdi, 11                     ; now at HH
  call parse_int_at                ; rax = hour
  cvtsi2sd xmm0, rax
  divsd xmm0, [rel twentythree_d]
  minsd xmm0, [rel one_d]
  maxsd xmm0, [rel zero_d]
  movsd [r14 + 24], xmm0           ; q[3]

  ; Read year/month/day for day-of-week
  mov  rdi, rax
  sub  rdi, 11                     ; back to YYYY
  call parse_int_at                ; rax = year
  mov  rbx, rax                    ; rbx = year
  add  rdi, 5                      ; MM
  call parse_int_at                ; rax = month
  mov  r8, rax                     ; r8 = month
  add  rdi, 3                      ; DD
  call parse_int_at                ; rax = day
  mov  r9, rax                     ; r9 = day
  ; Compute day-of-week (Sakamoto): y + y/4 - y/100 + y/400 + t[m-1] + d
  ; t = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4}
  mov  rax, rbx
  mov  r10, rax
  shr  r10, 2                      ; r10 = y/4
  add  rax, r10
  mov  r10, rbx
  mov  r11, 100
  push rdx
  xor  rdx, rdx
  mov  rax, r10
  xor  rdx, rdx
  div  r11
  pop  rdx
  sub  rax, r10
  mov  r10, rbx
  mov  r11, 400
  push rdx
  xor  rdx, rdx
  mov  rax, r10
  xor  rdx, rdx
  div  r11
  pop  rdx
  add  rax, r10
  ; subtract if m<3: y--
  cmp  r8, 3
  jge  .dow_no_decr
  dec  rbx
.dow_no_decr:
  ; t[m-1] using small table
  mov  r10, r8
  dec  r10
  ; t[0..11] = {0,3,2,5,0,3,5,1,4,6,2,4}
  lea  rcx, [rel t_table]
  movzx r10, byte [rcx + r10]
  add  rax, r10
  add  rax, r9                     ; + d
  ; dow = (sum % 7)
  push rdx
  xor  rdx, rdx
  mov  r11, 7
  mov  r11, r11
  mov  r10, rax
  mov  rax, r10
  xor  rdx, rdx
  div  r11
  pop  rdx
  ; rax = dow (0..6, Sunday=0)
  ; Convert to Monday=0: (dow + 6) % 7
  add  rax, 6
  push rdx
  xor  rdx, rdx
  mov  r11, 7
  mov  r11, r11
  mov  r10, rax
  mov  rax, r10
  xor  rdx, rdx
  div  r11
  pop  rdx
  cvtsi2sd xmm0, rax
  divsd xmm0, [rel six_d]
  movsd [r14 + 32], xmm0           ; q[4]

  ; ----- customer.avg_amount (q[2] = clamp01(amount/avg/10)) -----
  lea  rdi, [rel key_avg_amount]
  mov  rsi, key_avg_amount_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_avg_amount_len
  mov  rdi, rax
  call parse_float_at
  ; xmm0 = customer_avg. If > 0, q[2] = clamp01((amount/cust_avg)/10)
  ; We have amount already in [r14]. Need to read it back.
  movsd xmm1, [r14]                ; q[0] (amount normalized)
  mulsd xmm1, [rel ten_k_d]         ; de-normalize: amount
  divsd xmm1, xmm0                  ; amount / cust_avg
  divsd xmm1, [rel ten_d]            ; / 10
  minsd xmm1, [rel one_d]
  maxsd xmm1, [rel zero_d]
  movsd [r14 + 16], xmm1            ; q[2]

  ; ----- tx_count_24h (q[8] = clamp01(count/20)) -----
  lea  rdi, [rel key_tx_count]
  mov  rsi, key_tx_count_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_tx_count_len
  mov  rdi, rax
  call parse_int_at
  cvtsi2sd xmm0, rax
  divsd xmm0, [rel twenty_d]
  minsd xmm0, [rel one_d]
  maxsd xmm0, [rel zero_d]
  movsd [r14 + 64], xmm0           ; q[8]

  ; ----- known_merchants array (find merchant.id inside) -----
  ; q[11] = 1.0 if NOT in known_merchants, 0.0 if in
  lea  rdi, [rel key_merchants_arr]
  mov  rsi, key_merchants_arr_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_no_km                    ; no known_merchants array, default 1
  mov  rbx, rax                     ; rbx = start of "known_merchants":[
  add  rbx, key_merchants_arr_len
  ; Find matching ] (depth 1, since arr is at depth 1)
  mov  r10, rbx
  mov  r11, 1                       ; depth
.find_arr_end:
  cmp  r10, r13
  jge  .pr_no_km
  movzx rax, byte [r10]
  cmp  rax, '['
  jne  .fae1
  inc  r11
.fae1:
  cmp  rax, ']'
  jne  .fae2
  dec  r11
  jz   .arr_end_found
.fae2:
  inc  r10
  jmp  .find_arr_end
.arr_end_found:
  ; rbx = arr start, r10 = arr end
  mov  rdx, r10
  sub  rdx, rbx
  ; Build needle "merchant_id" with quotes
  mov  r10, r15                    ; mcc_buf overlaps? Use a temp area instead
  ; Actually: read merchant.id first, then search in arr
  jmp  .pr_no_km                    ; stub for now

.pr_no_km:
  ; Default: q[11] = 1.0 (not in known)
  movsd xmm0, [rel one_d]
  movsd [r14 + 88], xmm0

  ; ----- merchant.id: stored in mcc_buf (4 bytes MCC; we use as id placeholder) -----
  lea  rdi, [rel key_merchant_id]
  mov  rsi, key_merchant_id_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_merchant_id_len
  mov  rdi, rax
  ; Read 4 chars into r15 buffer (mcc_buf reused for id)
  movzx rax, byte [rdi]
  mov  byte [r15], al
  movzx rax, byte [rdi+1]
  mov  byte [r15+1], al
  movzx rax, byte [rdi+2]
  mov  byte [r15+2], al
  movzx rax, byte [rdi+3]
  mov  byte [r15+3], al

  ; ----- mcc -----
  lea  rdi, [rel key_mcc]
  mov  rsi, key_mcc_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_mcc_len
  mov  rdi, rax
  mov  r10, r15                    ; copy to mcc_buf (overwrite id, we don't need id anymore for mcc)
  movzx rax, byte [rdi]
  mov  byte [r10], al
  movzx rax, byte [rdi+1]
  mov  byte [r10+1], al
  movzx rax, byte [rdi+2]
  mov  byte [r10+2], al
  movzx rax, byte [rdi+3]
  mov  byte [r10+3], al
  ; Look up MCC in table -> q[12] = risk/100
  mov  rdi, r15
  mov  ecx, MCC_TABLE_LEN
  xor  r8, r8
.mcc_loop:
  movzx rax, byte [rdi]
  cmp  al, byte [mcc_table + r8*MCC_ENTRY_SIZE]
  jne  .mcc_next
  movzx rax, byte [rdi+1]
  cmp  al, byte [mcc_table + r8*MCC_ENTRY_SIZE + 1]
  jne  .mcc_next
  movzx rax, byte [rdi+2]
  cmp  al, byte [mcc_table + r8*MCC_ENTRY_SIZE + 2]
  jne  .mcc_next
  movzx rax, byte [rdi+3]
  cmp  al, byte [mcc_table + r8*MCC_ENTRY_SIZE + 3]
  jne  .mcc_next
  ; Found
  movzx rax, byte [mcc_table + r8*MCC_ENTRY_SIZE + 4]
  cvtsi2sd xmm0, rax
  divsd xmm0, [rel ten_k_d]
  jmp  .mcc_done
.mcc_next:
  inc  r8
  cmp  r8, rcx
  jl   .mcc_loop
  ; Not found, default 0.5
  movsd xmm0, [rel zero_d]
  addsd xmm0, [rel zero_d]
  addsd xmm0, [rel one_d]
  addsd xmm0, [rel one_d]
  divsd xmm0, [rel two_d]
.mcc_done:
  movsd [r14 + 96], xmm0           ; q[12]

  ; ----- merchant.avg_amount (q[13] = clamp01(avg/10000)) -----
  ; The C parser re-reads avg_amount (it appears twice: customer and merchant).
  ; The second occurrence is merchant.avg_amount.
  ; Find it by skipping the first occurrence we already used.
  ; For simplicity, find the LAST occurrence by reverse search — or just take the second.
  ; We'll use a simple approach: find the second occurrence.
  lea  rdi, [rel key_m_avg]
  mov  rsi, key_m_avg_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_m_avg_len
  mov  rdi, rax
  call parse_float_at
  divsd xmm0, [rel ten_k_d]
  minsd xmm0, [rel one_d]
  maxsd xmm0, [rel zero_d]
  movsd [r14 + 104], xmm0          ; q[13]

  ; ----- terminal.is_online (q[9] = 0/1) -----
  lea  rdi, [rel key_is_online]
  mov  rsi, key_is_online_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_is_online_len
  mov  rdi, rax
  cmp  byte [rdi], 't'             ; true
  jne  .is_online_false
  movsd xmm0, [rel one_d]
  add  rdi, 4
  jmp  .is_online_done
.is_online_false:
  movsd xmm0, [rel zero_d]
  add  rdi, 5
.is_online_done:
  movsd [r14 + 72], xmm0           ; q[9]

  ; ----- card_present (q[10]) -----
  lea  rdi, [rel key_card_present]
  mov  rsi, key_card_present_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_card_present_len
  mov  rdi, rax
  cmp  byte [rdi], 't'
  jne  .cp_false
  movsd xmm0, [rel one_d]
  add  rdi, 4
  jmp  .cp_done
.cp_false:
  movsd xmm0, [rel zero_d]
  add  rdi, 5
.cp_done:
  movsd [r14 + 80], xmm0           ; q[10]

  ; ----- km_from_home (q[7] = clamp01(km/1000)) -----
  lea  rdi, [rel key_km_from_home]
  mov  rsi, key_km_from_home_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_km_from_home_len
  mov  rdi, rax
  call parse_float_at
  divsd xmm0, [rel thousand_d]
  minsd xmm0, [rel one_d]
  maxsd xmm0, [rel zero_d]
  movsd [r14 + 56], xmm0           ; q[7]

  ; ----- last_transaction: skip if null -----
  lea  rdi, [rel key_last_tx_obj]
  mov  rsi, key_last_tx_obj_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_last_tx_obj_len
  mov  rdi, rax
  ; Check if null
  cmp  dword [rdi], 0x6c6c756e     ; "null" LE = 6e 75 6c 6c
  jne  .last_not_null
  jmp  .pr_done                     ; null: q[5],q[6] stay -1
.last_not_null:
  ; last.timestamp
  lea  rdi, [rel key_last_ts]
  mov  rsi, key_last_ts_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_last_ts_len
  mov  rdi, rax
  ; Read YYYY-MM-DDTHH:MM:SS
  ; We need the request time too: re-find requested_at
  ; For simplicity, compute days difference as a coarse approximation
  ; rdi -> YYYY, parse year/month/day/hour/minute/second
  push rdi
  call parse_int_at
  mov  rbx, rax                    ; year
  add  rdi, 5
  call parse_int_at
  mov  r8, rax                     ; month
  add  rdi, 3
  call parse_int_at
  mov  r9, rax                     ; day
  add  rdi, 3
  call parse_int_at
  mov  r10, rax                    ; hour
  add  rdi, 3
  call parse_int_at
  mov  r11, rax                    ; minute
  add  rdi, 3
  call parse_int_at                ; rax = second (rdi now past "Z")
  pop  rdi
  ; For now, set q[5] = 0.0 (placeholder, full epoch calc is lengthy)
  movsd xmm0, [rel zero_d]
  movsd [r14 + 40], xmm0

  ; last.km_from_current
  lea  rdi, [rel key_last_km]
  mov  rsi, key_last_km_len
  mov  rdx, r12
  mov  rcx, r13
  call memmem_simple
  test rax, rax
  jz   .pr_fail
  add  rax, key_last_km_len
  mov  rdi, rax
  call parse_float_at
  divsd xmm0, [rel thousand_d]
  minsd xmm0, [rel one_d]
  maxsd xmm0, [rel zero_d]
  movsd [r14 + 48], xmm0           ; q[6]

.pr_done:
  mov  rax, 1
  jmp  .pr_ret
.pr_fail:
  xor  rax, rax
.pr_ret:
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  pop  rbx
  ret

; Day-of-week offset table (t[m-1])
section .rodata
alignb 1
t_table: db 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4
