## Unreleased

## v0.13.3
Improvements:
* Updated dependencies:
  * github.com/hashicorp/go-retryablehttp v0.7.2 -> v0.7.4
  * github.com/hashicorp/vault/sdk v0.9.0 -> v0.9.2
  * github.com/stretchr/testify v1.8.2 -> v1.8.4

## v0.13.2
* Dependency upgrades 

## v0.13.1
* No new features

## v0.13.0
* No new features

## v0.12.0
* No new features

## 0.11.1 (Aug 1, 2022)

Bug Fixes:
* Fix bug in boolean parsing for initialize [[GH-38](https://github.com/hashicorp/vault-plugin-database-elasticsearch/pull/38)]

## 0.11.0 (May 25th, 2022)

Improvements:
* Use the new `/_security` base API path instead of `/_xpack/security` when managing elasticsearch [[GH-37](https://github.com/hashicorp/vault-plugin-database-elasticsearch/pull/37)]
