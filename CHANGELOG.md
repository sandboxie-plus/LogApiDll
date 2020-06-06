# Changelog
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [1.0.5] - 2020-06-06

### Fixed
- Greatly Improved load speeds through batch enabling of hooks.
- fix memory corruption issue


## [1.0.4] - 2020-05-31

### Added
- MinHook library

### Changed
- Switched from messages to pipes for communication
- Now using MinHook library to install hooks due to issues with Sbies hooking function

### Fixed
- Applications crashing on startup

### Removed
- Removed dependencies on custom private headers
-- instead ProcessHackers collection of Native API headers is used
-- alternatively Sandboxies header collection can be used as well