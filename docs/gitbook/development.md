# Development

Panther is a collection of serverless applications deployed within your AWS account. The frontend is a React application which runs in a Docker container \(via ECS\), and the backend is a collection of compute \(Lambda\), storage \(DynamoDB / S3\), and other supporting services.

The sections below provide guidance on how to extend Panther to meet your individual needs.

## Environment

You can use the Docker environment from the [quick start](quick-start.md#deployment) instructions for development. However, it's faster to compile and test the code locally.

### Dependencies

Install [Go](https://golang.org/doc/install#install) 1.13+, [Node](https://nodejs.org/en/download/) 10+, and [Python](https://www.python.org/downloads/) 3.7+.

For MacOS w/ homebrew:

```bash
brew install go node python3
```

Add go tools to your environment:

```bash
export GOPATH=$HOME/go PATH=$PATH:$GOPATH/bin
```

Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv1.html), which usually works best with the [bundled installer](https://docs.aws.amazon.com/cli/latest/userguide/install-bundle.html):

```bash
curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
unzip awscli-bundle.zip
sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
```

Install [Docker](https://docs.docker.com/install/) and make sure the daemon is running in the background.

Install [Mage](https://magefile.org/#installation):

```bash
go get github.com/magefile/mage
```

Finally, install the remaining development libraries:

```bash
mage setup:all
```

### Mage

Panther uses [mage](https://magefile.org/), a Go tool similar to `make` , to manage the development lifecycle.

Run `mage` from the repo root to see the list of available commands:

```text
Targets:
  build:api           Generate Go client/models from Swagger specs in api/
  build:lambda        Compile Go Lambda function source
  clean               Remove auto-generated build artifacts
  deploy              Deploy application infrastructure
  doc:cfn             Cfn will generate user documentation from deployment CloudFormation
  fmt                 Format source files
  glue:sync           Sync glue table partitions after schema change
  setup:all           Install all development dependencies
  setup:go            Install goimports, go-swagger, and golangci-lint
  setup:python        Install the Python virtual env
  setup:web           Npm install
  teardown            Destroy all Panther infrastructure
  test:cfn            Lint CloudFormation templates
  test:ci             Run all required checks
  test:cover          Run Go unit tests and view test coverage in HTML
  test:go             Test Go source
  test:integration    Run integration tests (integration_test.go,integration.py)
  test:python         Test Python source
  test:web            Test web source
```

You can easily chain `mage` commands together, for example: `mage fmt test:ci deploy`

## Testing

1. Run backend test suite: `mage test:ci`
2. Run frontend test suite: `npm run lint`
3. Run integration tests against a live deployment: `mage test:integration`
   - **WARNING**: integration tests will erase all Panther data stores
   - To run tests for only one package: `PKG=./internal/compliance/compliance-api/main mage test:integration`

## Deploying and Updating

To update your deployment of Panther, follow the steps below:

1. Checkout the latest release:
   1. `git fetch origin master`
   2. `git checkout tags/v0.3.0`
2. Clean the existing build artifacts: `mage clean`
3. Deploy the latest application changes: `mage deploy`

## Repo Layout

Since the majority of Panther is written in Go, the repo follows the standard [Go project layout](https://github.com/golang-standards/project-layout):

|         Path         | Description                                                                               |
| :----------------------: | ----------------------------------------------------------------------------------------- |
|  [**api**](https://github.com/panther-labs/panther/tree/master/api)   | Input/output models for communicating with Panther's backend APIs   |
| [**deployments**](https://github.com/panther-labs/panther/tree/master/deployments)   | CloudFormation templates for deploying Panther itself or integrating the accounts you want to scan   |
| [**docs**](https://github.com/panther-labs/panther/tree/master/docs)  | Documentation, license headers, README, images, code of conduct, etc  |
| [**internal**](https://github.com/panther-labs/panther/tree/master/internal) | Source code for all of Panther's Lambda functions  |
| [**pkg**](https://github.com/panther-labs/panther/tree/master/pkg)  | Standalone Go libraries that could be directly imported by other projects. This folder is [licensed](https://github.com/panther-labs/panther/blob/master/LICENSE) under Apache v2  |
| [**tools**](https://github.com/panther-labs/panther/tree/master/tools)  | Magefile source and other build infrastructure  |
| [**web**](https://github.com/panther-labs/panther/tree/master/web)   | Source for the Panther web application  |
