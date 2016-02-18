#!/bin/bash
counter=0
while [ $counter -lt 5 ];do
    make check|sed -e 1b -e '$!d' >> result
    let counter=counter+1
done

