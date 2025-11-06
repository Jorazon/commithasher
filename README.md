# Git Commit Hash Prefixer

Give your commit hashes leading zeroes!

Inspired by [Тsфdiиg's 𝕏 post](https://x.com/tsoding/status/1855713113221234836)

## Usage

By default the prefix searched for is at least three leading zeroes `000`

```
./hasher
```

Giving a valid lowercase hex string as the first option searches for that prefix

```
./hasher bada55
```

## TODO

- [x] arg to give desired prefix instead of just current hard coded `000`
- [x] speed it up using `git commit-tree` instead of `git commit --amend`
- [x] speed it up by running spinner in parallel

