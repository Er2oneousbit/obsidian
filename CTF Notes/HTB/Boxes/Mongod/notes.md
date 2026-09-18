# HTB - Mongod

#HTB #Mongod #MongoDB #NoSQL #Easy

Target: 10.129.170.247

## Services

- 22/tcp    ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
- 27017/tcp mongod   MongoDB 3.6.8

## Versions

- OS: Ubuntu (gcc 9.3.0-17ubuntu1~20.04)
- OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
- MongoDB 3.6.8
- OpenSSL 1.1.1f

## Recon

```bash
nmap -sV --open -oA initial_scan 10.129.170.247
# 22/tcp open  ssh  OpenSSH 8.2p1 Ubuntu 4ubuntu0.5

nmap -p- --open -oA full_tcp_scan 10.129.170.247
# Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
# 22/tcp    open  ssh
# 27017/tcp open  mongod

nmap -sC -p 22,27017 -oA script_scan 10.129.170.247
```

## Foothold

Unauthenticated MongoDB on the default port — connect directly, no credentials:

```bash
./mongo mongodb://10.129.170.247:27017
```

> [!note] Nothing past the connection was recorded in the original notes — no database enumeration, no flag. See [[Services/Database Services/MongoDB|MongoDB]] for the enumeration commands (`show dbs`, `use <db>`, `db.<coll>.find()`) this box is built to exercise.
