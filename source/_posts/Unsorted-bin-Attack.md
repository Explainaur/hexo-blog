---
title: Unsorted-bin Attack
date: 2020-01-18 17:54:25
tags:
	- thinking
---

## 前言
&emsp;&emsp;这两天学习Unsorted-bin Attack的过程中遇到了一些令我十分困惑的细节，我只好一边读glibc源码一边排查问题，记录一下我的心路历程，免得下次遇到又忘了。

## Unsorted-bin Attack
&emsp;&emsp;Unsorted-bin Attack的主要原理是通过修改unsorted-bin chunk的bk指针，然后可以将某段内存修改为一个很大的数。其实就是修改unsorted bin的front end chunk的bk指针，然后重新请求分配该chunk这个时候会发生一下事情：

