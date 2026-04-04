
./prob:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fe9]        # 403ff8 <__gmon_start__@Base>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	f2 ff 25 e3 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fe3]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:	0f 1f 00             	nop    DWORD PTR [rax]
  401030:	f3 0f 1e fa          	endbr64
  401034:	68 00 00 00 00       	push   0x0
  401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <_init+0x20>
  40103f:	90                   	nop

Disassembly of section .plt.sec:

0000000000401040 <read@plt>:
  401040:	f3 0f 1e fa          	endbr64
  401044:	f2 ff 25 cd 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fcd]        # 404018 <read@GLIBC_2.2.5>
  40104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000401050 <_start>:
  401050:	f3 0f 1e fa          	endbr64
  401054:	31 ed                	xor    ebp,ebp
  401056:	49 89 d1             	mov    r9,rdx
  401059:	5e                   	pop    rsi
  40105a:	48 89 e2             	mov    rdx,rsp
  40105d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401061:	50                   	push   rax
  401062:	54                   	push   rsp
  401063:	45 31 c0             	xor    r8d,r8d
  401066:	31 c9                	xor    ecx,ecx
  401068:	48 c7 c7 78 11 40 00 	mov    rdi,0x401178
  40106f:	ff 15 7b 2f 00 00    	call   QWORD PTR [rip+0x2f7b]        # 403ff0 <__libc_start_main@GLIBC_2.34>
  401075:	f4                   	hlt
  401076:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40107d:	00 00 00 

0000000000401080 <_dl_relocate_static_pie>:
  401080:	f3 0f 1e fa          	endbr64
  401084:	c3                   	ret
  401085:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40108c:	00 00 00 
  40108f:	90                   	nop

0000000000401090 <deregister_tm_clones>:
  401090:	b8 30 40 40 00       	mov    eax,0x404030
  401095:	48 3d 30 40 40 00    	cmp    rax,0x404030
  40109b:	74 13                	je     4010b0 <deregister_tm_clones+0x20>
  40109d:	b8 00 00 00 00       	mov    eax,0x0
  4010a2:	48 85 c0             	test   rax,rax
  4010a5:	74 09                	je     4010b0 <deregister_tm_clones+0x20>
  4010a7:	bf 30 40 40 00       	mov    edi,0x404030
  4010ac:	ff e0                	jmp    rax
  4010ae:	66 90                	xchg   ax,ax
  4010b0:	c3                   	ret
  4010b1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4010b8:	00 00 00 00 
  4010bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004010c0 <register_tm_clones>:
  4010c0:	be 30 40 40 00       	mov    esi,0x404030
  4010c5:	48 81 ee 30 40 40 00 	sub    rsi,0x404030
  4010cc:	48 89 f0             	mov    rax,rsi
  4010cf:	48 c1 ee 3f          	shr    rsi,0x3f
  4010d3:	48 c1 f8 03          	sar    rax,0x3
  4010d7:	48 01 c6             	add    rsi,rax
  4010da:	48 d1 fe             	sar    rsi,1
  4010dd:	74 11                	je     4010f0 <register_tm_clones+0x30>
  4010df:	b8 00 00 00 00       	mov    eax,0x0
  4010e4:	48 85 c0             	test   rax,rax
  4010e7:	74 07                	je     4010f0 <register_tm_clones+0x30>
  4010e9:	bf 30 40 40 00       	mov    edi,0x404030
  4010ee:	ff e0                	jmp    rax
  4010f0:	c3                   	ret
  4010f1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4010f8:	00 00 00 00 
  4010fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401100 <__do_global_dtors_aux>:
  401100:	f3 0f 1e fa          	endbr64
  401104:	80 3d 25 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f25],0x0        # 404030 <__TMC_END__>
  40110b:	75 13                	jne    401120 <__do_global_dtors_aux+0x20>
  40110d:	55                   	push   rbp
  40110e:	48 89 e5             	mov    rbp,rsp
  401111:	e8 7a ff ff ff       	call   401090 <deregister_tm_clones>
  401116:	c6 05 13 2f 00 00 01 	mov    BYTE PTR [rip+0x2f13],0x1        # 404030 <__TMC_END__>
  40111d:	5d                   	pop    rbp
  40111e:	c3                   	ret
  40111f:	90                   	nop
  401120:	c3                   	ret
  401121:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401128:	00 00 00 00 
  40112c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401130 <frame_dummy>:
  401130:	f3 0f 1e fa          	endbr64
  401134:	eb 8a                	jmp    4010c0 <register_tm_clones>

0000000000401136 <vuln>:
  401136:	f3 0f 1e fa          	endbr64
  40113a:	55                   	push   rbp
  40113b:	48 89 e5             	mov    rbp,rsp
  40113e:	48 83 ec 20          	sub    rsp,0x20
  401142:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
  401149:	00 
  40114a:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
  401151:	00 
  401152:	48 c7 45 f0 00 00 00 	mov    QWORD PTR [rbp-0x10],0x0
  401159:	00 
  40115a:	48 c7 45 f8 00 00 00 	mov    QWORD PTR [rbp-0x8],0x0
  401161:	00 
  401162:	ba 30 00 00 00       	mov    edx,0x30
  401167:	48 8d 75 e0          	lea    rsi,[rbp-0x20]
  40116b:	bf 00 00 00 00       	mov    edi,0x0
  401170:	e8 cb fe ff ff       	call   401040 <read@plt>
  401175:	90                   	nop
  401176:	c9                   	leave
  401177:	c3                   	ret

0000000000401178 <main>:
  401178:	f3 0f 1e fa          	endbr64
  40117c:	55                   	push   rbp
  40117d:	48 89 e5             	mov    rbp,rsp
  401180:	e8 b1 ff ff ff       	call   401136 <vuln>
  401185:	b8 00 00 00 00       	mov    eax,0x0
  40118a:	5d                   	pop    rbp
  40118b:	c3                   	ret

Disassembly of section .fini:

000000000040118c <_fini>:
  40118c:	f3 0f 1e fa          	endbr64
  401190:	48 83 ec 08          	sub    rsp,0x8
  401194:	48 83 c4 08          	add    rsp,0x8
  401198:	c3                   	ret
