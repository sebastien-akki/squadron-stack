# Stack health

Each Squadron project's stack at a glance: versions at or near their end of life, and the known vulnerabilities of its Composer and npm packages.

## Use

- **Stack health** in an agent's toolbar opens the panel for the agent's project. **Scan** reads:
  - the versions of **PHP** (`.lando.yml`, then `composer.json`), **Symfony**, **Drupal** and **Sylius** (`composer.lock`), **Node.js** (`.nvmrc`, `.lando.yml`, then `package.json`) and **MariaDB** or **MySQL** (`.lando.yml`), each against [endoflife.date](https://endoflife.date): supported, end of life within 6 months, or past it, with the latest release of its branch;
  - `composer audit --locked` on `composer.lock`: each package with its advisories, severity and CVE, and the abandoned packages;
  - `npm audit --package-lock-only` on `package-lock.json`: the counts by severity and the packages, direct dependencies first.
- A scanned project is scanned again every day. When something new comes up (a new advisory, a version past its end of life), a notification says so and the button gets a badge.
- **Fix with an agent** opens New agent in the project with the list of updates to make.
- Agents can call `stack_report` to scan their project and read the report. Claude Code asks you first.

## What it asks Squadron for

- **Run `git`**: to read the project's files as committed and find its root.
- **Run `docker`**: `composer audit` in `composer:2` and `npm audit` in `node:22`, the project mounted read-only, with network to reach Packagist's and npm's advisory databases.
- **Run `id`**: to run the containers as you.
- **Network `endoflife.date`**: the end-of-life dates.

## Build

```sh
rustup target add wasm32-wasip2
cargo test
cargo build --release --target wasm32-wasip2
```

Then in Squadron: Settings › Extensions › Add an extension › A folder on this computer.
