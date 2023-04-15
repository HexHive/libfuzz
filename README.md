# LibFuzz++

Purpose: LibFuzz++ automatically generates drivers (unit-tests) starting from a library source.

The whole framework is composed of three main components:

- Static analyzer: it takes a library soure code an emits a list of constraints.
- Driver generator: it uses the library constraints (from the static analyzer) and synthetizes the drivers (+ seeds).
- Fuzzing: we use libfuzz to fuzz the new generated drivers.

## How to Install

The environment has been designed for VS Code. 
The Dockerfile in the root folder builds the container, that will be used as development environment in VS Code.

**To install Docker extension and make your dev env:**

https://code.visualstudio.com/docs/remote/containers#_quick-start-open-an-existing-folder-in-a-container

**Tips to use your GH SSH from inside the Docker**

https://code.visualstudio.com/docs/remote/containers#_sharing-git-credentials-with-your-container

## How to set a target (add a new library)

TODO


## Specific Gudies

Ad-hoc guides for specific components of the project

- [Library Analysis](./docs/Analysis.md)
- [Driver Generation](./docs/DriverGeneration.md)
- [Fuzzing a Driver](./docs/FuzzingDrivers.md)
- Triage (TODO)
- Statistics (TODO)
