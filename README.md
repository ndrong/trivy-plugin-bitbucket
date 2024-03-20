# trivy-plugin-bitbucket

This repository contains a modified version of [this plugin](https://github.com/umax/trivy-plugin-sonarqube). Thanks to the original author!


A [Trivy](https://github.com/aquasecurity/trivy) plugin that converts JSON report to [Bitbucket](https://bitbucket.org) format. The idea is to scan project dependencies with Trivy and post results to Bitbucket through external issues report. This way you can get code scanning and dependency scanning results in one place.

## Installation

install plugin:

```
$ trivy plugin install github.com/ndrong/trivy-plugin-bitbucket
```

check the installation:

```
$ trivy plugin list
```

NOTE: you need the [Python](https://www.python.org/) interpreter installed to be able to run this plugin.

## Usage

run `trivy` with JSON report enabled:

```
$ trivy fs --format=json --output=trivy.json PATH
```

convert Trivy report to Bitbucket compatible report:

```
$ trivy bitbucket trivy.json > bitbucket.json
```

redefine `filePath` field of Bitbucket result. For example, if you scan Dockerfile with `trivy image` command, `filePath` field will contain url of docker image instead of file name. As result, Bitbucket will skip this report, because docker image url is not a source file in terms of Bitbucket. `--filePath` option allows you to set Dockefile name:

```
$ trivy bitbucket trivy.json -- filePath=Dockerfile > bitbucket.json
```

## Bitbucket CI

Here is a small example how to use this plugin in Bitbucket CI to post Trivy results to Bitbucket.

```
// TODO: Add an example here.
```
