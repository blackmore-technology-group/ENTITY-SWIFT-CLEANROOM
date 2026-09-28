# Swift Package Index publication

This repository is structurally ready for normal Swift package discovery:

- public GitHub repository;
- root `Package.swift`;
- explicit executable products including `EntitySwiftCleanroom` and `PassportV34`;
- package smoke verifies `swift package describe` and release-builds the exposed products;
- existing clean-room verification remains green.

## Remaining external release step

Before submitting to Swift Package Index:

1. choose a semantic-version tag that accurately identifies the exact source/campaign being distributed;
2. run dependency review, clean-room verification and registry package smoke on that source;
3. create a new tag rather than moving/reusing historical tags;
4. verify the tagged repository still passes `swift package dump-package` / package description and release build;
5. submit the public Git URL to Swift Package Index.

No Swift Package Index credential needs to be stored in this repository for normal public-package discovery.

## Evidence boundary

Swift Package Index publication improves discovery/installability of this BTG-controlled Swift baseline. It is not unrelated third-party validation or an independently authored ENTITY implementation.
