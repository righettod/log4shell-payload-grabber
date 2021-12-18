#!/bin/bash
mvn clean package
mvn dependency:copy-dependencies
mkdir -p target/dist/lib
cp target/dependency/*.jar target/dist/lib/
cp target/*.jar  target/dist/
cp run.sh target/dist/
