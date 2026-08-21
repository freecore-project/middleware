--- zettarepl/transport/base_ssh.py.orig	2023-05-10 15:17:12 UTC
+++ zettarepl/transport/base_ssh.py
@@ -158 +158 @@
-        for key_class in (paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key):
+        for key_class in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key):
