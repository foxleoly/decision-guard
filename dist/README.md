# Prebuilt decision-guard binaries

`decision-guard-<target-triple>` is the release build of `../rust`; `SHA256SUMS` lists the checksum of each one.
`scripts/install.sh` copies the one for the current machine to `~/.decision-guard/bin/decision-guard` after
verifying its checksum, and refuses to install on a mismatch.

Produce them with `rust/scripts/build-dist.sh`. It builds only for the machine it runs on (the host triple), so each
target must be built on a machine of that target. Targets available now are exactly the files listed in `SHA256SUMS`;
on any other platform `install.sh` stops with an error until someone builds and commits that target.
