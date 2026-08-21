"""Convert & Import (the internal development record, #415, #445).

One guided lane with two sources and one sink:

- a stopped iocage jail, or a Linux OCI workload (an image reference or an
  export bundle taken off a Docker/Podman host), on the way in;
- an Application record, on the way out, on either the native Daemonless image
  with the workload's state carried across (a recipe knows the app) or the
  source Linux image itself under the Linux compatibility tier.

And the other way (the internal development record): an Application written out as a
Linux compose bundle, in exactly the format the export-bundle reader reads,
with its state in the layout the recipe's Linux image expects.

The engine never decides: ``detect`` reads, ``plan`` writes a typed document the
operator confirms, ``apply`` runs it as a job.  Nothing here creates, starts,
modifies or destroys a jail; every write lands on the Applications pool.
"""
