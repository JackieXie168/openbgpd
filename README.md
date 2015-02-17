## Courtesy of pfSense

This is a fork of OpenBSD's OpenBGPd that

a. Builds on FreeBSD
b. Has full TCP-MD5 support without the native PF_KEY implementation (Make sure to configure the local address per peer, that is what it uses to establish the IKE SAs)

You will need to compile a kernel with TCP MD5 Sig support.

In your config file,

options IPSEC  #IP security (requires device crypto)
device  crypto
options TCP_SIGNATURE #include support for RFC 2385
