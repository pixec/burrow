# pixec-burrow

The Python SDK for [Burrow](https://burrow.pixec.net): microVM sandboxes for untrusted code, run on your own hardware.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/pixec-burrow?label=pypi)](https://pypi.org/project/pixec-burrow/)

## Install

```sh
pip install pixec-burrow
```

Python 3.9 or newer.

```python
from burrow import Sandbox

with Sandbox.create(template="python").deleting() as sandbox:
    result = sandbox.subprocess.run(["echo", "hello"], capture_output=True, text=True)
    print(result.stdout)  # "hello\n"
```

## Sponsors

Thanks to the following sponsors for helping fund Burrow's development.
To become a sponsor, write to `oss+burrow[at]pixec.net`.

| Company | About |
| --- | --- |
| [BoxCompute](https://boxcompute.ai) | BoxCompute provides cloud computers for AI agents. Each agent gets its own Linux virtual machine that keeps running after you close the browser; connect tools such as Claude Code, Codex or Cursor, or describe a task to BoxCompute's built-in agent, which sets up the software, runs your app, and gives you a live preview link. |
| [berrybyte](https://berrybyte.net) | berrybyte hosts game servers for players and their friends. It runs more than twenty games, including Minecraft, Hytale, Rust, Palworld and Valheim, with one-click modpack installs, a browser dashboard, automatic off-site backups and DDoS protection, in US East, US West and EU Central. It also offers dedicated servers. |

## Documentation

The documentation is available at [burrow.pixec.net](https://burrow.pixec.net/sdk/python/overview).

## License

The Python SDK is licensed under the MIT License, in [LICENSE](LICENSE). Burrow itself is licensed under the GNU Affero General Public License, version 3.
