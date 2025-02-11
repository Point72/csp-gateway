<a href="https://github.com/point72/csp-gateway">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/point72/csp-gateway/raw/main/docs/img/logo-name-dark.png?raw=true">
    <img alt="csp-gateway logo, overlapping blue chevrons facing right" src="https://github.com/point72/csp-gateway/raw/main/docs/img/logo-name.png?raw=true" width="400">
  </picture>
</a>

<br />

[![PyPI](https://img.shields.io/pypi/v/csp-gateway.svg?style=flat)](https://pypi.python.org/pypi/csp-gateway)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](https://github.com/Point72/csp-gateway/LICENSE)
[![Build Status](https://github.com/Point72/csp-gateway/actions/workflows/build.yml/badge.svg)](https://github.com/Point72/csp-gateway/actions/workflows/build.yml)

## Overview

`csp-gateway` is a framework for building high-performance streaming applications.
It is is composed of four major components:

- Engine: [csp](https://github.com/point72/csp), a streaming, complex event processor core
- API: [FastAPI](https://fastapi.tiangolo.com) REST/WebSocket API
- UI: [Perspective](https://perspective.finos.org) and React based frontend with automatic table and chart visualizations
- Configuration: [ccflow](https://github.com/point72/ccflow), a [Pydantic](https://docs.pydantic.dev/latest/)/[Hydra](https://hydra.cc) based extensible, composeable dependency injection and configuration framework

For a detailed overview, see our [Documentation](https://github.com/Point72/csp-gateway/wiki/Overview).

![A brief demo gif of csp-gateway ui, graph viewer, rest api docs, and rest api](https://raw.githubusercontent.com/point72/csp-gateway/main/docs/img/demo.gif)

## Installation

`csp-gateway` can be installed via [pip](https://pip.pypa.io) or [conda](https://docs.conda.io/en/latest/), the two primary package managers for the Python ecosystem.

To install `csp-gateway` via **pip**, run this command in your terminal:

```bash
pip install csp-gateway
```

To install `csp-gateway` via **conda**, run this command in your terminal:

```bash
conda install csp-gateway -c conda-forge
```

## Getting Started

See [our wiki!](https://github.com/Point72/csp-gateway/wiki)

## Development

Check out the [contribution guide](https://github.com/Point72/csp-gateway/wiki/Contribute) for more information.

## License

This software is licensed under the Apache 2.0 license. See the [LICENSE](https://github.com/Point72/csp-gateway/blob/main/LICENSE) file for details.
