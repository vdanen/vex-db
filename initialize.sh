#!/usr/bin/sh

archive=$(curl https://security.access.redhat.com/data/csaf/v2/vex/archive_latest.txt)
today="vex-$(date +%Y-%m-%d)"

curl -OL https://security.access.redhat.com/data/csaf/v2/vex/${archive}

mkdir ${today}
tar xf ${archive} -C ${today}

sqlite3 vex.db <vex-db.sql

time python3 import-vex-db.py ${today} --database-url "sqlite:///vex.db"
