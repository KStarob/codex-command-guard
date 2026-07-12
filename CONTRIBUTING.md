# Contributing

Contributions are welcome through GitHub Pull Requests.

## Before Opening A Pull Request

1. Fork the repository or create a branch if you have write access.
2. Keep changes focused and explain the security behavior they affect.
3. Add regression fixtures for every parser or policy behavior change.
4. Run:

   ```bash
   swift run command-guard-tests
   swift build -c release
   swift scripts/run-canaries.swift --binary .build/release/codex-command-guard
   ```

5. Confirm that no secrets, personal paths, generated build output, or
   `.DS_Store` files are included.

Pull Requests must pass the repository's macOS CI before they can be merged to
`main`. Maintainers may request changes or decline proposals that broaden the
project beyond its narrow emergency-brake scope.

## Security Reports

Do not publish a working security bypass in an Issue. Follow the private
reporting instructions in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the
repository's Apache License 2.0.
