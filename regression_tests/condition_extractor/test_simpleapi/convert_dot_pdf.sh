#!/bin/bash

for apifun in create first second close third foo
do
    if [ -f "postdom_$apifun.dot" ]; then
        dot -Tpdf postdom_$apifun.dot -opostdom_$apifun.pdf
    else 
        echo "postdom_$apifun.dot does not exist"
    fi

    if [ -f "dom_$apifun.dot" ]; then
        dot -Tpdf dom_$apifun.dot -odom_$apifun.pdf
    else
        echo "dom_$apifun.dot does not exist"
    fi
done