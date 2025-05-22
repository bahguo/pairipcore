# pairipcore
Further research based on
[pairipcore](https://github.com/Solaree/pairipcore), focusing on the virtual
machine (VM) used to virtualize code in Android apps as a protection mechanism (**P**l**A**y**I**nteg**RI**ty**P**rotect - pairip).

> [!IMPORTANT]
> Google designed the VM to be custom for every release of an application. The
> analysis provided here acan be used up to the point where opcodes are analyzed.
> A workaround is WIP!

> [!NOTE]
> A detailed writeup is work-in-progress and will be published to GitHub Pages
> soon. Decompiler and Disassembler are WIP!
## Disclaimer
The information provided is solely meant for educational purposes only! and is not intended to encourage malicious practice.

## General Overview
Pairipcore prevents any kind of repacking, tampering, code injecting for the app, usage of such programs as [frida-server](https://frida.re/docs/android/). Optionally, it can prevent usage of the app for rooted users. More on [Github Pages]( https://matrixeditor.github.io/pairipcore-vm/)

### Basics
- [x] Integrity check (Java side, C++ library)
- [x] Pseudo-VM code injection
- [x] C++ library control flow & code obfuscation
- [x] Usage of [`dlopen`](https://man7.org/linux/man-pages/man3/dlopen.3.html), [`dlsym`](https://man7.org/linux/man-pages/man3/dlsym.3.html), [`dlclose`](https://man7.org/linux/man-pages/man3/dlopen.3.html) for dynamic import of bionic libc functions, [`syscall`](https://man7.org/linux/man-pages/man2/syscall.2.html) and [`SVC 0`](https://developer.arm.com/documentation/dui0489/c/arm-and-thumb-instructions/miscellaneous-instructions/svc)-based custom function. All needed to make analysis harder
- [x] Basic anti-debugger ([`prctl`](https://man7.org/linux/man-pages/man2/prctl.2.html), [`clone`](https://man7.org/linux/man-pages/man2/clone.2.html), [`waitpid`](https://man7.org/linux/man-pages/man2/wait.2.html), [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html))
- [x] `/proc/self/maps`, `/proc/self/status` checks ([`openat`](https://man7.org/linux/man-pages/man2/open.2.html), [`close`](https://man7.org/linux/man-pages/man2/close.2.html), [`read`](https://man7.org/linux/man-pages/man2/read.2.html), [`lseek`](https://man7.org/linux/man-pages/man2/lseek.2.html), [`fstat`](https://man7.org/linux/man-pages/man2/fstat.2.html), [`fstatfs`](https://man7.org/linux/man-pages/man2/fstatfs.2.html))
- [x] [system property functions](https://android.googlesource.com/platform/bionic/+/master/libc/include/sys/system_properties.h), [`access`](https://man7.org/linux/man-pages/man2/access.2.html), [`opendir`](https://man7.org/linux/man-pages/man3/opendir.3.html), [`readddir`](https://man7.org/linux/man-pages/man3/readdir.3.html), [`closedir`](https://man7.org/linux/man-pages/man3/closedir.3.html) directories and properties checks
- [x] Full frida-server check (not only default port, like Promon Shield does)

Most of those and more are done by another famous app protection, [Promon Shield](https://github.com/KiFilterFiberContext/promon-reversal)

## Technical Overview
### Java Side
The basic code structure looks like this:

![image](https://github.com/Solaree/pairipcore/assets/115794865/cf3235c3-fd97-4926-8b76-8ef481467e1e)

If we will check `Application.java`, we will see something like this:
```java
package com.pairip.application;

import android.content.Context;
import com.pairip.SignatureCheck;
import com.vpn.free.hotspot.secure.vpnify.App; /* the main app package goes here,
											in my case it was Vpnify */

public class Application extends App {
  public void attachBaseContext(Context context)  {
	  SignatureCheck.verifyIntegrity(context);
	  super.attachBaseContext(context);
  }
}
```
As we can see, Pairipcore does integrity check
```java
package com.pairip;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Base64;
import android.util.Log;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SignatureCheck {
	private static final String ALLOWLISTED_SIG = "Vn3kj4pUblROi2S+QfRRL9nhsaO2uoHQg6+dpEtxdTE=";
	private static final String TAG = "SignatureCheck";
	private static String expectedLegacyUpgradedSignature = "ag4imYhJd4ISc+m2klK8n1Oq2WId2REza1aYcssrVwc=";
	private static String expectedSignature = "ag4imYhJd4ISc+m2klK8n1Oq2WId2REza1aYcssrVwc=";
	private static String expectedTestSignature = "ag4imYhJd4ISc+m2klK8n1Oq2WId2REza1aYcssrVwc=";

	private static class SignatureTamperedException extends RuntimeException {
		public SignatureTamperedException(String message) {
			super(message);
		}
	}
  
	public static void verifyIntegrity(Context context) {
		String str;
		try {
			str = Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(context.getPackageManager().getPackageInfo(context.getPackageName(), 64).signatures[0].toByteArray()), 2);
		} catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException unused) {
			str = null;
		} if (!verifySignatureMatches(str) && !expectedTestSignature.equals(str) && !ALLOWLISTED_SIG.equals(str))
			throw new SignatureTamperedException("Apk signature is invalid.");
		Log.i(TAG, "Signature check ok");
	}

	public static boolean verifySignatureMatches(String signature) {
		return expectedSignature.equals(signature) || expectedLegacyUpgradedSignature.equals(signature);
	}

	private SignatureCheck() {
	}
}
```
Actually those aren't interesting and can be easily bypassed with removing call of the `verifyIntegrity` method, let's explore deeper..

In `VMRunner.java` in the corresponding class we can see next:
```java
public class VMRunner {
    private static final int PACKAGE_MANAGER_TRIES = 5;
    private static final String TAG = "VMRunner";
    private static String apkPath = null;
    private static Context context = null;
    private static String loggingEnabled = "false";

    public static native Object executeVM(byte[] vmCode, Object[] args);

    static {
        System.loadLibrary("pairipcore");
    }

    public static class VMRunnerException extends RuntimeException {
        public VMRunnerException(String message) {
            super(message);
        }

        public VMRunnerException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static void setContext(Context context2) {
        context = context2;
    }

    public static Object invoke(String vmByteCodeFile, Object[] args) {
        if (isDebuggingEnabled())
            Log.i(TAG, "Executing " + vmByteCodeFile);
        try {
            byte[] readByteCode = readByteCode(vmByteCodeFile);
            long currentTimeMillis = System.currentTimeMillis();
            Object executeVM = executeVM(readByteCode, args);
            if (isDebuggingEnabled())
                Log.i(TAG, String.format("Finished executing %s after %d ms.", vmByteCodeFile, Long.valueOf(System.currentTimeMillis() - currentTimeMillis)));
            return executeVM;
        } catch (IOException e) {
            throw new VMRunnerException("Error while loading bytecode.", e);
        }
    }
  ...
}
```

The code parts we need are 
```java
    public static native Object executeVM(byte[] vmCode, Object[] args);

    static {
        System.loadLibrary("pairipcore");
    }
    ...

    public static Object invoke(String vmByteCodeFile, Object[] args) ...
```
`executeVM` is the native method, which implementation can be found in the native C++ library, `libpairipcore.so`. Problem lies in that symbols are stripped, so we must use our brain and internet to find the address of it. Let's use frida-server for that (of course our application will crash, but before we can hook import of native JNI method.
```javascript
function find_RegisterNatives() {
  let symbols = Module.enumerateSymbolsSync("libart.so");
  let addrRegisterNatives = null;

  for (let i = 0; i < symbols.length; i++) {
    let symbol = symbols[i];

    if (symbol.name.indexOf("art") >= 0 && symbol.name.indexOf("JNI") >= 0 && symbol.name.indexOf("RegisterNatives") >= 0 && symbol.name.indexOf("CheckJNI") < 0) {
      addrRegisterNatives = symbol.address;

      hook_RegisterNatives(addrRegisterNatives);
    }
  }
}

function hook_RegisterNatives(addrRegisterNatives) {
  if (addrRegisterNatives != null) {
    Interceptor.attach(addrRegisterNatives, {
      onEnter(args) {
        // let executeVM = NULL;
        let class_name = Java.vm.tryGetEnv().getClassName(args[1]);
        let methods_ptr = ptr(args[2]);
        let method_count = parseInt(args[3]);
  
        for (let i = 0; i < method_count; i++) {
          let name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
          let sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
          let fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

          let name = Memory.readCString(name_ptr);
          let sig = Memory.readCString(sig_ptr);
          let symbol = DebugSymbol.fromAddress(fnPtr_ptr);

          if (name == "executeVM") {
            // executeVM = parseInt(symbol.toString().split("!")[1]);
            console.log(`[RegisterNatives] class: ${class_name}, name: ${name} signature: ${sig}, fnPtr: ${fnPtr_ptr}, fnOffset: ${symbol}, callee: ${DebugSymbol.fromAddress(this.returnAddress)}`);
            break;
          }
        }
      }
    });
  }
}

rpc.exports.init = find_RegisterNatives;
```
Output will be like this:
`[RegisterNatives] class: com.pairip.VMRunner, name: executeVM signature: ([B[Ljava/lang/Object;)Ljava/lang/Object;, fnPtr: 0x701ef730c8, fnOffset: 0x701ef730c8 libpairipcore.so!0x560c8, callee: 0x701ef71414 libpairipcore.so!0x54414`

In `fnOffset` at the end we see offset of `exeecuteVM` in pairipcore native library.
Now many people will say:
> We can just strip the Java code, C++ library and everything is ready!

No, Google aren't stupid and the pairipcore mechanism is complicated: to prevent removing of the Java code and binary they used neat trick: pairipcore creates pseudo-VM files which are needed for program work, those files typically lie in `assets` folder. Program uses the `invoke` method which accordingly calls the `executeVM` function, offset of which we found before:
![image_2024-04-03_19-33-27](https://github.com/Solaree/pairipcore/assets/115794865/4402e086-de0c-40a5-b9a6-799d575bd4f1)

Congratulations! The Java part is finished! What's next?

# More analysis

[PairIP Protection Remover](https://github.com/void-eth/pairip-protection-remover)
A simple, cross-platform tool for bypassing Google's PairIP protection in Flutter applications. Available in both Python and Bash versions.
