#!/bin/bash

cat $1 | grep -Eo "://[^/]+" | sort | uniq -c | sort -bgr
