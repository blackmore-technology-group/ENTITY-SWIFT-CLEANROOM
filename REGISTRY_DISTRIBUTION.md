# Swift package distribution boundary

This repository is a BTG-controlled ENTITY clean-room/conformance baseline. Swift Package Index or other package discovery should make the executable verifier easier to find and run, but must not be described as independent third-party validation.

The package exposes named executable products while preserving the existing implementation and frozen conformance campaigns. Registry/discovery changes must not alter sealed inputs, expected classifications, hashes, or fail-closed behavior.
