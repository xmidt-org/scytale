# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
- add docker automation [#91](https://github.com/xmidt-org/scytale/pull/91)

## [v0.4.1]
- fix bug in wiring of WRP and Fanout handler chains [#89](https://github.com/xmidt-org/scytale/pull/89)

## [v0.4.0]
- add configurable feature to authorize WRP PartnerIDs from predefined JWT claims [#86](https://github.com/xmidt-org/scytale/pull/86)

## [v0.3.1]
- Added fix to correctly parse URL for capability checking [#87](https://github.com/xmidt-org/scytale/pull/87)

## [v0.3.0]
- added configurable way to check capabilities and put results into metrics, without rejecting requests [#80](https://github.com/xmidt-org/scytale/pull/80)

## [v0.2.0]
- updated release pipeline to use travis [#73](https://github.com/xmidt-org/scytale/pull/73)
- bumped bascule, webpa-common, and wrp-go for updated capability configuration [#75](https://github.com/xmidt-org/scytale/pull/75)
- fix feature for passing partnerIDs from JWT to fanout WRP messages. Enforce nonempty partnerIDs [#81](https://github.com/xmidt-org/scytale/pull/81)

## [v0.1.5]
- converting glide to go mod
- bumped bascule version and removed any dependencies on webpa-common secure package

## [v0.1.4]
Switching to new build process

## [v0.1.1] Tue Mar 28 2017 Weston Schmidt - 0.1.1
- initial creation


[Unreleased]: https://github.com/Comcast/scytale/compare/v0.4.1...HEAD
[v0.4.1]: https://github.com/Comcast/scytale/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/Comcast/scytale/compare/v0.3.1...v0.4.0
[v0.3.1]: https://github.com/Comcast/scytale/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/Comcast/scytale/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/Comcast/scytale/compare/v0.1.5...v0.2.0
[v0.1.5]: https://github.com/Comcast/scytale/compare/v0.1.4...v0.1.5
[v0.1.4]: https://github.com/Comcast/scytale/compare/v0.1.1...v0.1.4
[v0.1.1]: https://github.com/Comcast/scytale/compare/v0.1.0...v0.1.1
