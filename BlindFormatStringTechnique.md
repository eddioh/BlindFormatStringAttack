# Format String Technique
## Bypassing PIE and ASLR with a Single Format String

### Vulnerable Program
For this technique, the target is a Linux 32 bit executable with a single blind format string vulnerability.

```
#include <stdio.h>
#include <stdlib.h>

void write_log(){
    FILE *fptr = fopen("/dev/null", "w");
    char buf[512];
    scanf("%511s", buf);

    fprintf(fptr, buf);
    fflush(stdout);
    
    fclose(fptr);
    
    return;
}

void logger(){
    write_log();
    puts("all done have a great day!");
}

int main(){
    logger();
}
```
The executable is compiled with gcc with -m32 otherwise all compiler default settings on. Importantly this means that Position Independent Executable (PIE) is enabled on this binary, and Address space layout randomization (ASLR) is also enabled on the kali OS where this experiment is executed. This kali distro is running glibc version 2.38, MD5 hash 5dd2dbb635262fa25ed99aa6a4a67b54.


## Background

On review of the source code there is an externally controlled format string vulnerability on line 10 with the fprintf call. A common exploitation technique here would be to first leak addresses of interest from the PIE binary, libc or the stack to allow you to locate return address locations or global offset table (GOT) entries and locations. Following this you then pass these addresses in a second payload and write to that positional offset with %n.

The %n specifier writes the numbers of characters printed so far by the format string back into memory at address stored in the specified offset. Fine-grained control of what value is written to memory is generally accomplished with specific padding values. For example, the payload “%1$1000c%10$hn\x08\x00\x56\x55” would print a single character located at positional argument 1, and pad it by 1000, printing 1000 characters. Then, if our positional argument 10 points into your payload at the right location, the following specifier will write the halfword 1000 into the lower two bytes at the address we passed in our payload. This requires knowledge of both where you want to write to and what you want to write as you pass the second payload, knowledge which was gained with the initial memory leak.

That technique is not possible with this binary for two reasons:

- the vulnerable fprintf call only occurs once before the program finishes so if memory was leaked it would be randomized again on future attempts,

- the output is blind to the user since it is written to /dev/null meaning it is not possible to get any feedback from the format specifiers being processed by fprintf.

This is a realistic scenario, for example a networked binary that logs erroneous header fields to a local file, blind to the user supplying the format specifiers, for example CVE-2023-22374. In these cases, it is often concluded that this vulnerability can only be leveraged to crash the program.

This writeup will demonstrate a technique that makes it possible to redirect flow of execution with binaries with these single-shot and blind format string vulnerabilities.

## Exploit

This section will step through each portion of exploit.py in this repo.

The payload that will be supplied to this program is going to cause fprintf to be called many times, so the flow of this portion of the writeup will be to break down each separate call or group of calls to fprintf and highlight interesting features of each payload.

It is important to note up front that this is one very large payload separated by newlines, each being processed by a separate call to fprint. Considering we get no feedback from the program, the exploit is entirely static and could be supplied to the target program in a single interaction such as through a network packet, local file or environment variable.

#### First Sendline

The goal of this first sendline is to solve a key problem: a lack of stack space.

This binary is very simple, so there are not many interesting targets of %n calls on the stack when fprintf is called. An interesting target would be a stack aligned memory address on the stack that points to another stack aligned memory address, both living on the stack at consistent offsets following fprintf's format string.

Ideal candidates that meet these criteria are the chain of base pointers that are laid on the stack when nested functions are called. This chain of base pointers point to each other all the way down the back trace of the stack. However all we have is write_log -> logger -> main in the backtrace as fprintf is called.

To get around this, the first portion of the payload aims to overwrite the global offset table for puts with the memory address of the start of the logger function. Considering puts is called within logger this will turn logger into a recursive function, which we can then let run a few times to build up a healthy set of base pointers to user later.

**Payload:**  %c…%c%*c%11476c%c%c%c%n%53848c%192\$hn%65270c%141$hn

This payload immediately highlights the need for two key new techniques, successive writes and variable padding specifier.

##### Technique 1 – Successive Writes

The plan is write to a location with %n, and then write to that new location with a second %n within the same call to fprintf. In most cases this is not possible with format specifiers, as memory addresses being written to by %n are usually gathered immediately as fprint is called. For example, the format string %1\$n%2$n  (assuming the memory address at positional argument 1 points to the location of positional argument 2) does not work as a successive write, what happens is that the number of characters printed so far are written to the original values inside arguments 1 and 2, not the new value placed into argument 2 by %1$n.

What I found though is that this behavior differs for the incremental specifiers, that is passing a specifier without a specific positional argument, for example %c. What happens with the incremental specifiers is that any side effect of these operations occurs left to right in the format string. Then, whenever the first positional argument is encountered, such as %75\$n, the values at each positional argument are gathered at that time. In the original example if you were to change it to %n%2\$n this does work, because the incremental %n will grab positional argument 1 first, write to it and then will take this new value and use it for the %2\$n. This can be extended to any argument as long as you stay in incremental mode up to the first %n write, then you can switch to positional argument mode and write to that new location. This is critical to allow us to write to arbitrary memory locations.

##### Technique 2 – Variable Padding Specifier

This technique abuses printf's variable padding specifier to pad the output based the value of memory addresses to defeat address randomization for %n writes. %n writes the number of characters printed so far to the memory address stored at a particular positional argument. If we pad based off a memory address, we can then print that memory address back into memory somewhere else. For an incremental specifier we can use %*c to variably pad the output, and printf will look at the following positional argument to find that number. For a positional argument, the syntax is %1\$*127\$c to print the character printed from positional argument 1 padded by the value stored at positional argument 127. It is treated as a 4-byte signed integer, which is then used to set the padding. If the value pointed to is a negative number, the absolute value is taken, and the padding is set to that value instead.

We will abuse this by pointing the variable padding at a PIE binary memory address, which for 32 bit the page begins at 0x5RRR R000, where the R's specify a common ASLR implementation for this page of memory. Luckily this is a positive 4-byte integer, so the output will be padded by a very large number. We now can write this value back into memory after padding a few more characters to point at any location within binary memory space, such as the global offset table. This technique combines well with the successive writes technique to allow us to write any PIE memory address to arbitrary memory locations in a single blind call to fprintf.

The breakdown of this payload:

1. Print 141 incremental characters using %c's. This is important to stay in incremental mode to allow successive writes.

2. that we are at positional argument 142, if we do variable padding now, we will pad based on a PIE binary memory location, so we pass %*c.

3. Now that we have padded with this randomized memory address, we pad a few more characters based on the relative offset of this location and the GOT entry for puts: %11476c.

4. Staying in incremental mode, we add a couple more %c's to get to the positional argument that we can perform successive writing on.

5. We now are looking at the positional argument of a memory address that is a good candidate for two successive writes, so we write the GOT table entry address here with %n.

6. The next portion of the payload completes one intermediate pad and write, this value is important for later but will push past this for now. Important to note that now we can use positional specifiers since the incremental first write is complete. %53848c%192\$hn

7. Now the goal is to pad with enough characters to get the lower two bytes to point back at the memory address at the start of logger, to create our recursive function. We are abusing the fact that puts has yet been called, so in the GOT table the upper two bytes are still pointing to the Procedure Linking Table (PLT) table which match the upper two bytes of logger. %65270c

8. Finally, we go to where the destination of the incremental write in step 5 above to complete the successive write technique and right to the GOT table. This works because we stayed in incremental mode all the way to the first %n, after which we could start using positional arguments directly. Note we are only writing a half byte since our padding in step 6 overflowed into the upper halfword %141\$hn.
   
This payload has accomplished that goal of turning logger into a recursive function, so we now will simply allow it to loop a few times to build up a healthy chain of base pointers to use later on.

After it has looped enough times, it is time to start sending interesting payloads again. This time the goal is to overwrite the return address of the current stack frame of write_log to loop here many times, which will leave our chain of base pointers at consistent positional arguments for our format string.

#### Second Sendline
**Payload:**  %c…%c%149c%hhn%217\$n%1$*225\$c%141$hn%217\$hn
Payload breakdown:

1. Print 136 incremental characters using %c's to get the incremental argument to point at the base pointer of the lower stack frame, we then pad by 149 and write to the lowest byte with an hhn. This portion of the exploit is a guess. We know that the return addresses lowest byte will be 0xRC with R being an ASLR value, so we take a guess it will be 0x1C and run the payload until it lands. This works for a proof of concept considering a 1 in 16 chance however with more time there may be ways to determine this value without guessing ( c%...%c%149c%hhn ).

2. Then the upper two bytes of positional argument 217 are cleared since it will be used to store a 16 bit value momentarily, %217\$n.

3. Assuming the guess is correct, a pointer to the return address of the write_log function is now on the stack, so we now need to overwrite it with a call to write_log to loop back to fprintf again without crashing. Padding is based on the value we stored in step 6 last time, which is the value of the call write_log address minus the number of characters we've printed so far since we haven't printed any randomized values yet, which will set us up to jump the call to write_log, %1$*225$c%141\$hn.

4. We then save the number a copy of the number of characters printed so far to the lower halfword of argument 217, which will come into play in the next portion, %217\$hn.

#### Third Sendline – Large Loop #1

We now have the ability to loop this stack frame as many times as we want, however a big issue is that as soon as we pad based on a randomized memory address, we no longer know how many characters we are printing, so we have no way to set the lower 2 bytes to zero. This is a problem considering libc is not at a fixed offset from the binary’s memory location, and we can’t get around padding with address for the call to write_log if we want to stay in our consistent loop. If I then pad based on a libc address I now have the lower 2 bytes of libc plus the lower two bytes of the address to write_log, which will be nonsense.

To address this the next phase aims to figure out which value to pad by to clear the last two bytes. This happens to be the complement of the last two bytes of the write_log call. To find this value the plan is to effectively take the value of these last two bytes and multiply it by 0xFFFF, giving the complement of this value. While we don't know what this initial value is as we write the exploit, we did save this value onto the stack on step 4 in the previous sendline. So, the plan is to loop 0xFFFF times, each time overwriting the return address, and then padding this value with an intermediate incrementor writing the result back to the incrementor on the stack. This will be the equivalent of adding this value to itself many times, eventually determining the complement of it. Once we have the complement, if we pad by that value after padding the return value, it will clear the last two bytes leaving us free to pad by a different region of memory.

The payload in this phase is similar to the previous sendlines barring one annoying edge case. Along the way it is possible that the intermediate value lands on 0, for example if the lower two bytes of the call write_log is 0x6276 and on the way to multiplying it 0xFFFF times you hit 0x8000 times the intermediate value of 0x6276 times 0x8000 is 0. So, on the next loop we will do something like this: %1$*221$c where argument 221 is the intermediate incrementor value, and since it is currently 0 we attempt to pad zero times however printf never truncates with padding so it will still print the one character, so 1 is added instead of 0. This will throw everything off, so an adjustment must be made. It was discovered through experimentation that if we instead print the value zero as a decimal specifier and then set the precision to zero it will print nothing if there is no padding. If we change %1$*221$c to %223$*221\$.d it will now still properly pad nonzero intermediate values and print nothing if the padding value is zero.

After this large loop is finished, we have the complement stored at the argument pointed to by argument 217, which happens to be argument 221.

#### Fourth Sendline – Large Loop #2

This sets us up for another large loop, because while we want the value of libc, this region of memory starts at 0xf, meaning it is a negative number. When we pad based on this number the absolute value is taken instead for padding.

To address this, we go through the same kind of loop as the previous large loop, however this time if we take the complement of this absolute value, the return is the actual value of the last two bytes of the padded libc address.

This loop is effectively the same process as the one before, however, the output of the last loop is used to reset the last two bytes to 0 before padding based on the libc absolute value, padding based on the incrementor value then overwriting the incrementor value back onto the stack.

#### Final Steps

Once we've accomplished this, the rest is straight forward as we now have the last two bytes of a libc memory address on the stack. First, we setup the arguments to the libc system call by placing a pointer to the string 'sh' found in PIE binary space to just below the return address, then we overwrite a GOT table entry with the lower two bytes of system with a value that has a shared upper two bytes such as fprintf and overwrite the return address to call fprintf to call system with the correct arguments to pop a shell.

At the final return, return address points to the call to fprintf, and the next stack location stores a pointer to “sh” as argument, and that the got table entry for fprintf at memory address 0x56656010 has been modified to point to the beginning of the libc system function.

## Additional Info

**Does the variable padding technique work for 64 bit?**

Yes! Printf still grabs 4 bytes for the padding, so as long as the 31st bit is 0 it will work normally, if not the absolute value is taken. This makes working with 64 bit more of a guessing game as this 31st bit is a random value, so could pad as a positive or a negative number. Still doable, but more variable.

**This technique has a few disadvantages, some which are believed to be solvable and some which are unavoidable**

- Size of payload – The looping to find the complement of values for both resetting to zero and for undoing the absolute value operation makes the payload very large. It is likely this can be mitigated by potentially breaking it down into two single byte operations of 255 loops each. Ideally, if more interesting information is stored in PIE binary space, it would negate the need to go into libc at all.

- Size of the output – Padding based on memory addresses yields printf output of very large values, this exploit would print a few GBytes to disc if it wasn’t sending everything to /dev/null. This can be mitigated by limited how often one pads off of full address values, storing the lower two bytes whenever possible to reduce output size.

- Knowing Libc – Knowing the relative offsets for the stack and PIE locations are a reasonable assumption when crafting the exploit, however I also built this exploit knowing the version of libc on the target. This is a big disadvantage to this technique. It may be possible to use PIE space initially to setup a memory leak, but this is not possible if you don’t have stdin/stdout to the process such as in CVE-2023-22374. You would need to learn the version of libc some other way.


