# Git Commit hash prefixer

Give your commit hashes leading zeroes!

Inspired by [Тsфdiиg](https://x.com/tsoding/status/1855713113221234836)

## TODO

- speed it up
  - perhaps there is a way to use `git commit-tree` to find hashes faster, the current issue with this approach is the hash is different when amaended (timestamps?)
- arg to give desired prefix instead of just current hard coded `000`
