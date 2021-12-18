# Objective

[![Build package](https://github.com/righettod/log4shell-payload-grabber/actions/workflows/maven.yml/badge.svg?branch=main)](https://github.com/righettod/log4shell-payload-grabber/actions/workflows/maven.yml)

Tool to try to retrieve the java class used as dropper for the RCE.

The tool was developed and tested again the tool named [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit).

It is a [IntelliJ IDEA](https://www.jetbrains.com/idea/download) project.

# Requirements

[Java 8](https://adoptium.net/?variant=openjdk8&jvmVariant=hotspot) is required for compilation and execution because classes only present in this JDK are used for RMI information retieval.

Need Maven3+ for the building.

# Usage

See the [demonstration](demo.mp4) video.

# Compilation

Use the script named [package.sh](package.sh) and the package will be present in the **target/dist** folder.
