--- zettarepl/transport/ssh.py.orig
+++ zettarepl/transport/ssh.py
@@ -125,7 +125,14 @@
                 recv = pipe(self.compression.decompress, recv)
 
             if self.speed_limit is not None:
-                send = pipe(send, ["throttle", "-B", str(self.speed_limit)])
+                send = pipe(send, [
+                    "mbuffer",
+                    "-q",  # quiet - do not display the status on the standard error output
+                    "-Q",  # quiet - do not log the status in the log file
+                    "-m", f"{self.speed_limit}b",  # Use a total of size bytes for buffer
+                    "-r", str(self.speed_limit),   # the transfer limit for the reader
+                    "-R", str(self.speed_limit),   # the transfer limit for the writer
+                ])
 
             if self.direction == ReplicationDirection.PUSH:
                 commands = [send, cmd + [implode(["sh", "-c", f"{PATH} " + implode(recv)])]]
