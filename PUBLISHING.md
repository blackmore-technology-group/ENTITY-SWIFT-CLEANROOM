# Swift Package Index publication

This repository is structurally ready for normal Swift package discovery:

- public GitHub repository;
- root `Package.swift`;
- explicit executable products including `EntitySwiftCleanroom` and `PassportV34`;
- package smoke verifies `swift package describe` and release-builds the exposed products;
- existing clean-room verification remains green.

## Distribution version boundary

The intended first normal versioned distribution tag for the current qualified campaign is:

`v3.4.2`

That tag identifies the BTG-controlled v3.4.2 Global Passport campaign. It does not rename ENTITY Protocol 1.0 and it does not convert BTG-controlled evidence into independent validation.

## Remaining external release step

Before submitting to Swift Package Index:

1. confirm `main` is the exact source/campaign already qualified by dependency review, clean-room verification and registry package smoke;
2. confirm no existing `v3.4.2` tag exists and never move or rewrite a historical tag;
3. create `v3.4.2` at that reviewed commit;
4. verify the tagged repository still passes `swift package dump-package`, package description and release builds for the exposed products;
5. submit the public Git URL to Swift Package Index.

No Swift Package Index credential needs to be stored in this repository for normal public-package discovery.

## Evidence boundary

Swift Package Index publication improves discovery/installability of this BTG-controlled Swift baseline. It is not unrelated third-party validation or an independently authored ENTITY implementation.
