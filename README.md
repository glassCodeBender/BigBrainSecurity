# BigBrainSecurity

This program is a work in progress. 

Big Brain Security is a computer forensic automation program/IDS written primarily in Scala with Apache Spark. I'm 
also using python to develop a plugin for the Volatility Framework.

WARNING: AnalyzePrefetch.scala will produce inaccurate results for users running Windows 8 or later. The 
list of safe files the program tests for only includes file names for Windows 7 or earlier. 

See config.txt for details on how to customize the program.
