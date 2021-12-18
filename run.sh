#!/bin/bash
# If single jar is used the payload is not triggered so I use to expanded mode
echo "Java 8 required for compilation and execution!!!"
java -classpath "$(pwd)/lib/log4j-api-2.14.1.jar:$(pwd)/lib/log4j-core-2.14.1.jar:$(pwd)/get-payload.jar" lu.xlm.EntryPoint $1
