## code jam monitor

This simple script allows for selecting a Docker image to run. This uses podman because Docker's networking things are very strange.

### usage

Here's how to use this:

1. `pip install -r requirements.txt` in a virtualenv
2. rename `config.example.toml` to `config.toml`
3. fill out `config.toml`
4. `flask --app main sync`
5. `flask --app main run`
