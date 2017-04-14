# SourceCodeSniffer
The Source Code Sniffer is a poor man’s static code analysis tool (SCA) designed to highlight high risk functions (Injection, LFI/RFI, file uploads etc) across multiple web application development languages (ASP, Java, CSharp, PHP, Perl, Python, JavaScript, HTML etc) in a highly configurable manner.
Source Code Sniffer is written in Python 2.7 and supports both Windows and Linux.



## Static Code Analysis Features and Languages
|Language   |SQL Injection|LFI/RFI |XSS|File Traversal|File Uploads|XML Injection|JSON Injection|Command Injection|LDAP Injection|
|----------:|------------:|-------:|--:|-------------:|-----------:|------------:|-------------:|--------------:|-------------:|
|PHP        |             |        |   |              |            |             |              |               |              |
|Python     |             |        |   |              |            |             |              |               |              |
|Node.js    |             |        |   |              |            |             |              |               |              |
|GO         |             |        |   |              |            |             |              |               |              |
|ASP Classic| &#10004;    |&#10004;|   |              |            |             |              |               |              |
|ASP.NET    | &#10004;    |        |   |              |            |             |              |               |              |
|JAVA       |             |        |   |              |            |             |              |               |              |
|JavaScript |             |        |   |              |            |             |              |               |              |
|Ruby       |             |        |   |              |            |             |              |               |              |
|Ruby       |             |        |   |              |            |             |              |               |              |
|Perl       |             |        |   |              |            |             |              |               |              |
|HTML       |             |        |   |              |            |             |              |               |              |
|HTML5      |             |        |   |              |            |             |              |               |              |
|VBScript   |             |        |   |              |            |             |              |               |              |

##Syntax help
```
python SourceCodeSniffer.py -h

- Command Line Usage
	``# C:/Users/Haxz0r/PycharmProjects/SourceCodeSniffer/SourceCodeSniff [options]``

Options
-------
====================== ==============================================================
-c --configFiles        specify the config files (default=['Default.ini', 'ASP.ini', 'CSharp.ini'])
                        config files should be comma separated
-p --pathToScan         specify the path to scan (default=.)
                        use the forward slash / for both *nix and windows paths
-i --ignoreFiles        specify files to not scan (default=('.html', '.js', 'robots.txt'))
                        ignored files and file types should be comma separated 
-v --verbose            verbose mode
-d --debug              show debug output
-l --log                output to log file
====================== ==============================================================
Example:
 python SourceCodeSniffer.py -c ASP.ini,CSharp.ini,Default.ini,VBScript.ini -p c:/testpath/test/ -i .html,robots.txt
```

