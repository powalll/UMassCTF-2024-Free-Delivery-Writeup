# Free Delivery Writeup

---

## Summary:

---

Reversing - 77 Solves

Free Delivery is an medium android APK reversing challenge that’s suppose to give exposure to malware obfuscation and android static/dynamic analysis. 

**Challenge Prompt:** 

Mr. Krabs has decided to make a new food delivery app for the Krusty Krab but Plankton decided to make his own patched version. Loyal Krusty Krab customers are saying weird network traffic and shell commands are coming from the app! Can you figure out what's going on?

**Flag:** UMASS{0ur_d3l1v3ry_squ1d_w1ll_br1ng_1t_r1ght_0ver_!}

## Writeup:

---

Firstly, let’s throw the program into Jadx to further dive into the decompiled Java code. 

Looking at the AndroidManifest.xml, the main thing of interest is the startup Activity, identified by lines 12-13 of the manifest**.** Looking at android:name on line 10, we know we should be looking further into “**com.example.freedelivery.MainActivity”**. 

![Untitled](Free%20Delivery%20Writeup%20aaa953e4f62741b2831d5636cbe0f508/Untitled.png)

Based on the challenge prompt, we should keep our eyes out for ways that the app could potentially generating malicious network traffic and make shell commands. 

Looking at the initial code in MainActivity, there’s some functions that standout that might be worth looking further into: 

Class a shown below performs an async background task and contains multiple obfuscated strings. 

![Untitled](images/Untitled%201.png)

Looking at the first obfuscated string, it gets passed into the X0 function which seems to a simple base64 decode and cast to a string:

![Untitled](images/Untitled%202.png)

Now, we can label X0 as a base64 decode function in Jadx and determine the first obfuscated string, “aHR0cDovLzEyNy4wLjAuMToxMjU0” is “[http://127.0.0.1:1254](http://127.0.0.1:1254/)” when base64 decoded. In this case, the url is a placeholder but in the real world you’ll see domains or public IP Addresses referenced which are controlled by the malware author. 

The next part of the StringBuilder, line 49, passes the variable mainActivity2.f12220f which evaluates to build.Model (the device manufacturer model name/number), to the a1 function which performs a XOR on it with the SPONGEBOB string and base64 encodes it. The return value of this is then appended to the sb StringBuilder. 

![Untitled](images/Untitled%203.png)

Next, Q0 is passed with our current string and O0 on line 128 will be called with this string since the year variable will evaluate to 2024 and (Z0() * 23) + 45 = 2023 which means the else condition will always be triggered.

![Untitled](images/Untitled%204.png)

Finally, we get to the part where network requests are finally made and a HTTP request is made with the string we established before.

![Untitled](images/Untitled%205.png)

Essentially, the big picture of what’s happening is that the app is performing HTTP data exfiltration to a domain and getting device information such as the device model, performing some basic encryption, and then appending it as data in the HTTP request to later be deciphered. Lines 52-55 do the same as the first request but instead does so with the device MAC Address. We get to line 58 and it does the same thing but for a third time but it looks like the information exfiltrated has already been encrypted. 

Using the below script, we can decipher the first half of the flag:

```jsx
import base64

input = "AzE9Omd0eG8XHhEcHTx1Nz0dN2MjfzF2MDYdICE6fyMa"
XOR_string = b"SPONGEBOBSPONGEBOBSPONGEBOBSPONGEBOBSPONGEBOB"
a = base64.b64decode(input)
flag_part_1 = b''
for i in range(len(a)):
    flag_part_1 += (a[i] ^ XOR_string[i % len(XOR_string)]).to_bytes()
print(flag_part_1)
```

Next up, we should probably look for the weird shell commands that were mentioned earlier. With Jadx’s search feature, we couldn’t find any Java command execution with Runtime.exec() or ProcessBuilder() so it might be in native code! (FYI - native code is embedded C or C++ implemented through JNI. It’s commonly used in intensive games or graphics but also in malware obfuscation to hide functionality) 

**Reference:** [https://www.ragingrock.com/AndroidAppRE/reversing_native_libs.html](https://www.ragingrock.com/AndroidAppRE/reversing_native_libs.html)

Looking below, we see the native function rgae.t() and the freedelivery native library being loaded.

![Untitled](images/Untitled%206.png)

In order to analyze the native code, we can rename the .apk to .zip, and then analyze the [libfreedelivery.so](http://libfreedelivery.so) executables in the lib folder of the unzipped folder. Since the function is dynamically linked (based on the absence of RegisterNatives function), we’ll be able to find the corresponding function in Ghidra with Java_ prefix and class and method name separated by underscores. 

![Untitled](Free%20Delivery%20Writeup%20aaa953e4f62741b2831d5636cbe0f508/Untitled%207.png)

We finally see the source of the shell commands at line 37 with commands being sent through system! If you look at line 32, you should be able to extract the flag by looking at the data region and getting the XOR of it with 0x55. 

### Alternative Solution with Frida

---

So originally, I was hoping that the string obfuscation would be good enough to force you to use dynamic analysis but I couldn’t get that completely working in time 🙃. Here’s the intended Frida solution for anyone curious. 

Firstly, let’s write the Frida script to hook system and print its system call. 

ref: [https://erev0s.com/blog/how-hook-android-native-methods-frida-noob-friendly/](https://erev0s.com/blog/how-hook-android-native-methods-frida-noob-friendly/)

```jsx
Java.perform(function () {  
	var Activity = Java.use('com.example.freedelivery.MainActivity');

	//Hooks system call in native code and prints command sent to system
  	Interceptor.attach(Module.findExportByName("libfreedelivery.so", "system"), {
    		onEnter: function(args) {
        		console.log(args[0].readCString());
    		}
	});
	});
```

In Jadx, we can find usage of our native function and eventually trace it to the onClick on line 210

![Untitled](Free%20Delivery%20Writeup%20aaa953e4f62741b2831d5636cbe0f508/Untitled%208.png)

Since there’s only four buttons on the app, we can try pressing all of them and seeing if any of them reach the native code. However, the app crashes every time we press a button! Looking at lines 190-191, it looks like a division by 0 could be causing the app to crash if V0, P0, R0, S0, or U0 return true. 

Going through some of them, they essentially perform anti-emulation or debugging checks to make it harder to analyze. 

![Untitled](Free%20Delivery%20Writeup%20aaa953e4f62741b2831d5636cbe0f508/Untitled%209.png)

![Untitled](Free%20Delivery%20Writeup%20aaa953e4f62741b2831d5636cbe0f508/Untitled%2010.png)

Using Frida, we can hook all these functions to return false and bypass these crashes. 

```jsx
Java.perform(function () {  
	var Activity = Java.use('com.example.freedelivery.MainActivity');

	//Hooks and overrides anti-debugging/emulation functions that cause app to crash
	Activity.V0.implementation = function () {
    		return false;
 	};
  	Activity.P0.implementation = function () {
    		return false;
  	};
	Activity.R0.implementation = function () {
    		return false;
  	};
  	Activity.S0.implementation = function () {
    		return false;
  	};
  	Activity.U0.implementation = function () {
    		return false;
  	};

	//Hooks system call in native code and prints command sent to system
  	Interceptor.attach(Module.findExportByName("libfreedelivery.so", "system"), {
    		onEnter: function(args) {
        		console.log(args[0].readCString());
    		}
	});
	});
```

Running the following command and pressing the bottom right button should get us the following output:

```jsx
frida -U -l solve.js -f com.example.freedelivery
```

![Untitled](Free%20Delivery%20Writeup%20aaa953e4f62741b2831d5636cbe0f508/Untitled%2011.png)
