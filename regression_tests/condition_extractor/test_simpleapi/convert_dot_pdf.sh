#!/bin/bash

dot -Tpdf 7a86ce6b1a05f6e92d2bd7683484013e_create_postdom.txt.dot -o7a86ce6b1a05f6e92d2bd7683484013e_create_postdom.pdf

dot -Tpdf 7a86ce6b1a05f6e92d2bd7683484013e_create_dom.txt.dot -o7a86ce6b1a05f6e92d2bd7683484013e_create_dom.pdf

# for apifun in create first second close third foo indirect_test
# for apifun in create
# do
#     if [ -f "postdom_$apifun.dot" ]; then
#         dot -Tpdf postdom_$apifun.dot -opostdom_$apifun.pdf
#     else 
#         echo "postdom_$apifun.dot does not exist"
#     fi

#     if [ -f "dom_$apifun.dot" ]; then
#         dot -Tpdf dom_$apifun.dot -odom_$apifun.pdf
#     else
#         echo "dom_$apifun.dot does not exist"
#     fi
# done