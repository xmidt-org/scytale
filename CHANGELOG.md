# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Prevent Authorization header from getting logged. [#136](https://github.com/xmidt-org/scytale/pull/136)
- Bumped webpa-common version. [#137](https://github.com/xmidt-org/scytale/pull/137)

## [v0.4.9]
### Changed
- Update mentions of the default branch from 'master' to 'main'. [#111](https://github.com/xmidt-org/scytale/pull/111)
- Bumped bascule and webpa-common versions. [#118](https://github.com/xmidt-org/scytale/pull/118)
- simplified Makefile. [#124](https://github.com/xmidt-org/scytale/pull/124)
- prep for github actions. [#124](https://github.com/xmidt-org/scytale/pull/124)
- Update buildtime format in Makefile to match RPM spec file. [#125](https://github.com/xmidt-org/scytale/pull/125)
- Update service discovery environment creation to include datacenter watch feature [#120](https://github.com/xmidt-org/scytale/pull/120)
- Add initial OpenTelemetry integration. [#129](https://github.com/xmidt-org/scytale/pull/129) thanks to @Sachin4403
- Make OpenTelemetry feature optional. [#133](https://github.com/xmidt-org/scytale/pull/133)


## [v0.4.8]
- Add eventKey to service discovery metric [#110](https://github.com/xmidt-org/scytale/pull/110)

## [v0.4.7]
- Fixed error where path would override deviceID in stat path. [#108](https://github.com/xmidt-org/scytale/pull/108)

## [v0.4.6]
- Added Error Encoder [#107](https://github.com/xmidt-org/scytale/pull/107)
- Fixed 500 error when device header is not set to be 400 [#107](https://github.com/xmidt-org/scytale/pull/107)
- Fixed stat endpoint fanout to wrong endpoint [#107](https://github.com/xmidt-org/scytale/pull/107)

## [v0.4.5]
### Fixed
- Fixed scytale fannout error when a datacenter was empty by bumping webpa-common to 1.10.6 [#106](https://github.com/xmidt-org/scytale/pull/106)

## [v0.4.4]
### Fixed
- Fix scytale fannout via service discovery [#105](https://github.com/xmidt-org/scytale/pull/105)

## [v0.4.3]
### Changed
- Updated webpa-common version to 1.10.3. [#104](https://github.com/xmidt-org/scytale/pull/104)

## [v0.4.2]
### Added 
- Docker automation. [#91](https://github.com/xmidt-org/scytale/pull/91)

### Changed
- Register for specific OS signals. [#98](https://github.com/xmidt-org/scytale/pull/98)

### Fixed
- Fix the metric panic when attempting to deploy scytale with no endpoints. [#103](https://github.com/xmidt-org/scytale/pull/103)

## [v0.4.1]
- Fix bug in wiring of WRP and Fanout handler chains. [#89](https://github.com/xmidt-org/scytale/pull/89)

## [v0.4.0]
- Add configurable feature to authorize WRP PartnerIDs from predefined JWT claims. [#86](https://github.com/xmidt-org/scytale/pull/86)

## [v0.3.1]
- Added fix to correctly parse URL for capability checking. [#87](https://github.com/xmidt-org/scytale/pull/87)

## [v0.3.0]
- Added configurable way to check capabilities and put results into metrics, without rejecting requests. [#80](https://github.com/xmidt-org/scytale/pull/80)

## [v0.2.0]
- Updated release pipeline to use travis. [#73](https://github.com/xmidt-org/scytale/pull/73)
- Bumped bascule, webpa-common, and wrp-go for updated capability configuration. [#75](https://github.com/xmidt-org/scytale/pull/75)
- Fix feature for passing partnerIDs from JWT to fanout WRP messages. Enforce nonempty partnerIDs. [#81](https://github.com/xmidt-org/scytale/pull/81)

## [v0.1.5]
- Converting glide to go mod.
- bumped bascule version and removed any dependencies on webpa-common secure package.

## [v0.1.4]
- Switching to new build process.

## [v0.1.1] Tue Mar 28 2017 Weston Schmidt - 0.1.1
- Initial creation.


[Unreleased]: https://github.com/xmidt-org/scytale/compare/v0.4.9...HEAD
[v0.4.9]: https://github.com/xmidt-org/scytale/compare/v0.4.8...v0.4.9
[v0.4.8]: https://github.com/xmidt-org/scytale/compare/v0.4.7...v0.4.8
[v0.4.7]: https://github.com/xmidt-org/scytale/compare/v0.4.6...v0.4.7
[v0.4.6]: https://github.com/xmidt-org/scytale/compare/v0.4.5...v0.4.6
[v0.4.5]: https://github.com/xmidt-org/scytale/compare/v0.4.4...v0.4.5
[v0.4.4]: https://github.com/xmidt-org/scytale/compare/v0.4.3...v0.4.4
[v0.4.3]: https://github.com/xmidt-org/scytale/compare/v0.4.2...v0.4.3
[v0.4.2]: https://github.com/xmidt-org/scytale/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/xmidt-org/scytale/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/xmidt-org/scytale/compare/v0.3.1...v0.4.0
[v0.3.1]: https://github.com/xmidt-org/scytale/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/xmidt-org/scytale/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/xmidt-org/scytale/compare/v0.1.5...v0.2.0
[v0.1.5]: https://github.com/xmidt-org/scytale/compare/v0.1.4...v0.1.5
[v0.1.4]: https://github.com/xmidt-org/scytale/compare/v0.1.1...v0.1.4
[v0.1.1]: https://github.com/xmidt-org/scytale/compare/v0.1.0...v0.1.1
