## Certificate Store Monitor
Certificate Store Monitor based off of a concept by Steve Gibson of GRC.

## Summary
CSM is the security tool that I never knew I needed.  Based off of a concept initially broached by Steve Gibson on Security Now! Episode #551, this utility provides you with the ability to protect your Windows Certificate Store.  In an age where even hardware manufacturers are trying to infiltrate your certificate store, this is a tool that every privacy-conscious individual should have in their arsenal.

## Features

  * **Active Monitoring**:  CSM's WatchDog feature monitors the registry keys that contain the Windows Certificate Store.  If a change is made to any of these keys, it notifies you immediately and allows you to remove the new certificate.
  * **Passive Scanning**:  CSM provides a user-friendly wrapper around the  [SysInternals Suite Sigcheck Utility](https://technet.microsoft.com/en-us/sysinternals/bb897441.aspx).  Whenever CSM starts up, it uses SigCheck to check your certificate store against Microsoft's default list of trusted certificates.  If there are any non-default certificates found, CSM provides an interface for removing them.

## Installation

 * **Quick Setup**: A goal of this project was to be completely portable.  The compiled executable requires no installation.  **Simply download the compiled executable, extract it anywhere on your computer, and run it.**  You may receive a UAC prompt as the utility escalates its permissions.
    * **[Download the pre-compiled binary from the GNZ Systems website by clicking here!](https://www.gnzsystems.com/software/csm-0.0.1a-win32-python27.zip)**
  
 * **From Source**: CSM requries a few external modules.  They're included in the requirements.txt file.  On a Python 2.7 install simply run the command **pip install -r requirements.txt** to get yourself up and running!

## Moving Forward

  * **Refactoring, adding comments**
      For a project written from the ground up in 4 days, with no prior planning, the codebase is surprisingly readable.  However, it's still very messy and inefficient.  First priority is cleaning up the code base and adding comments to promote collaboration.

  * **Performance Optimization**
      Because there was very little prior planning, there are many redundant functions and unneccessary function calls at this point.  This impacts the application's overall performance.  Once the refactoring is complete, the next priority will be improving performance.

  * **User Interface Improvements**
      Currently, the application relies on dynamically generated VBScript notifications.  This is *not* ideal.  We are currently working on an improved interface design.  This interface will handle notifications, provide a tray icon, and provide an interface for accessing currently-unused functionality.

  * **Functionality**
      Due to the lack of an *actual* user interface, there is currently some dormant back-end functionality.  This functionality includes the ability to revert changes that this utility makes to the registry.

  * **Reduced reliance on SigCheck** 
      Preliminary testing shows that SigCheck doesn't find *all* of the rogue certificates that may be floating around in your certificate store.  Future versions will include an internal implementation of SigCheck, with improved checking against the Microsoft STL.

  * **Improved Active Monitoring** 
      The current version only monitors parts of the key stores that already contain keys.  This leaves some parts of the certificate store unmonitored, which may allow a certificate to be installed unnoticed.
