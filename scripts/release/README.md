# release

```sh
python -m scripts.release.build
```

Traverses the dependency graph for workspaces specified in `config.py`, builds workspace dependencies into wheels, then constructs a minimal `requirements.txt`.

It is the workspace's onus to declare a install script and copy it to the build output.