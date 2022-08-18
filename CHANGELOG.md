# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.6.7]
- JWT Migration [183](https://github.com/xmidt-org/scytale/issues/183)
  - updated to use clortho `Resolver` & `Refresher`
  - updated to use clortho `metrics` & `logging`
- Update Config
  - Use [uber/zap](https://github.com/uber-go/zap) for clortho logging
  - Use [xmidt-org/sallust](https://github.com/xmidt-org/sallust) for the zap config unmarshalling 
  - Update auth config for clortho
- Dependency update
  - Introduces new vuln https://www.mend.io/vulnerability-database/CVE-2022-29526
  - [github.com/hashicorp/consul/api v1.13.1 CVE-2022-29153 patched versions 1.9.17 1.10.10 1.11.5](https://github.com/advisories/GHSA-q6h7-4qgw-2j9p)
  - guardrails says github.com/gorilla/websocket v1.5.0 has a high vulnerability but no vulnerabilities have been filed
  
## [v0.6.5]
- Added validation of device ID in url for stat endpoint. [#175](https://github.com/xmidt-org/scytale/pull/175)

## [v0.6.4]
- Fixed stat fanout to not try to hit send endpoint. [#174](https://github.com/xmidt-org/scytale/pull/174)

## [v0.6.3]
- Fixed stat endpoint to use fanout prefix configuration. [#170](https://github.com/xmidt-org/scytale/pull/170)

## [v0.6.2]
- Updated spec file and rpkg version macro to be able to choose when the 'v' is included in the version. [#163](https://github.com/xmidt-org/scytale/pull/163)
- Reconfigured the Bascule Logger settings so that the logger isn't overwritten [#166](https://github.com/xmidt-org/scytale/pull/166)
- Added configurable v2 endpoint support. [#167](https://github.com/xmidt-org/scytale/pull/167)

## [v0.6.1]
- Fixed url parsing bug where we were leaving a '/'. [#161](https://github.com/xmidt-org/scytale/pull/161)

## [v0.6.0]
- Add consul registration. [#160](https://github.com/xmidt-org/scytale/pull/160)

## [v0.5.0]
- Updated api version in url to v3 to indicate breaking changes in response codes when an invalid auth is sent.  This change was made in an earlier release (v0.4.10). [#159](https://github.com/xmidt-org/scytale/pull/159)
- Decoupled fanout api version from scytale's api version. [#159](https://github.com/xmidt-org/scytale/pull/159)

## [v0.4.11]
- Bumped wrp version from v2 to v3.[#138](https://github.com/xmidt-org/scytale/pull/138)
- Bump bascule version for a security vulnerability fix and other required upgrades. [#140](https://github.com/xmidt-org/scytale/pull/140)
- Fixed string slice casting issue in an auth check. [#141](https://github.com/xmidt-org/scytale/pull/141)

## [v0.4.10]
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


[Unreleased]: https://github.com/xmidt-org/scytale/compare/v0.6.7...HEAD
[v0.6.5]: https://github.com/xmidt-org/scytale/compare/v0.6.5...v0.6.7
[v0.6.5]: https://github.com/xmidt-org/scytale/compare/v0.6.4...v0.6.5
[v0.6.4]: https://github.com/xmidt-org/scytale/compare/v0.6.3...v0.6.4
[v0.6.3]: https://github.com/xmidt-org/scytale/compare/v0.6.2...v0.6.3
[v0.6.2]: https://github.com/xmidt-org/scytale/compare/v0.6.1...v0.6.2
[v0.6.1]: https://github.com/xmidt-org/scytale/compare/v0.6.0...v0.6.1
[v0.6.0]: https://github.com/xmidt-org/scytale/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/xmidt-org/scytale/compare/v0.4.11...v0.5.0
[v0.4.11]: https://github.com/xmidt-org/scytale/compare/v0.4.10...v0.4.11
[v0.4.10]: https://github.com/xmidt-org/scytale/compare/v0.4.9...v0.4.10
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
