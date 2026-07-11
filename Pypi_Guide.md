# Publishing rotbyte to PyPI

A first-time, start-to-finish walkthrough for getting `rotbyte` onto the Python
Package Index — checked against the current `pyproject.toml` (version **1.3.0**,
zero runtime dependencies, `setuptools` backend). The name `rotbyte` is confirmed
unclaimed on PyPI, so there's no naming collision to work around.

| | |
|---|---|
| **Package** | rotbyte |
| **Current version** | 1.3.0 |
| **Build backend** | setuptools |

## Before you start — a quick glossary

- **PyPI vs. TestPyPI** — two entirely separate services with separate accounts,
  separate logins, separate API tokens. TestPyPI (`test.pypi.org`) is a sandbox
  for rehearsing an upload with zero consequences. Nothing you do there touches
  the real index.
- **sdist vs. wheel** — a build produces two files: a `.tar.gz` source
  distribution and a `.whl` wheel (a prebuilt, ready-to-install package). You
  upload both; pip prefers the wheel.
- **API token** — PyPI no longer accepts your account password for uploads. You
  generate a token (starts with `pypi-`) and use it as the password, with
  username literally set to `__token__`.

## Setup — do this once

### 1. Create your accounts

Register at `pypi.org/account/register`, and separately at
`test.pypi.org/account/register` — the two do not share logins. Use different
passwords or a password manager; treat them as unrelated services.

> **Required:** Turn on two-factor authentication on both accounts (Account
> Settings → Add 2FA). PyPI has required 2FA for all uploads since 2024 — you
> cannot skip this step. An authenticator app (1Password, Authy, Google
> Authenticator) is faster to set up than a hardware key.

### 2. Install the packaging tools

You need two tools that aren't part of rotbyte itself: `build` (creates the
sdist/wheel) and `twine` (uploads them securely). Install them in a scratch
virtual environment so they never mix with rotbyte's own zero-dependency
footprint.

```bash
python3 -m venv ~/.venvs/rotbyte-release
source ~/.venvs/rotbyte-release/bin/activate
python3 -m pip install --upgrade pip build twine
```

Re-activate this venv (the `source` line) any time you come back to do a release.

### 3. Generate a PyPI API token

On `pypi.org`: Account Settings → API tokens → Add API token. Because the
`rotbyte` project doesn't exist on PyPI yet, you can't scope the token to it
yet — choose **"Entire account"** scope for this first upload only.

> **Do this right after:** Once the first upload succeeds (Step 7), go back and
> generate a second token scoped to just the `rotbyte` project, then delete the
> account-wide one. An account-wide token that leaks can publish under any name
> you own; a project-scoped one can only touch rotbyte.

Repeat this on `test.pypi.org` for a separate TestPyPI token — you'll need both.

Store tokens in `~/.pypirc` so twine doesn't prompt every time:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmc...        # your real PyPI token

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-AgENdGVzdC5weXBpLm9yZw...  # your real TestPyPI token
```

```bash
chmod 600 ~/.pypirc
```

## Ship the first release

### 4. Build the distribution

From the repo root, with the release venv active:

```bash
rm -rf dist/ build/ *.egg-info
python3 -m build
```

This reads your existing `pyproject.toml` — no `setup.py` needed — and produces:

```
dist/rotbyte-1.3.0.tar.gz           # sdist
dist/rotbyte-1.3.0-py3-none-any.whl # wheel
```

### 5. Sanity-check the build

```bash
twine check dist/*
```

Then confirm the bundled setup guides actually made it into the wheel — this is
the one thing easy to get wrong, since `_rotbyte/docs/*.md` is wired through
`[tool.setuptools.package-data]` rather than being ordinary source:

```bash
unzip -l dist/rotbyte-1.3.0-py3-none-any.whl | grep docs/
```

You should see `email-notification-setup.md`, `macos-permissions.md`, and
`windows-task-scheduler.md` listed.

### 6. Rehearse on TestPyPI

Upload to the sandbox first. This is the step that catches metadata mistakes
before they're permanent.

```bash
twine upload --repository testpypi dist/*
```

Install it into a throwaway environment to prove the entry point and package
data both work end to end:

```bash
python3 -m venv /tmp/rotbyte-smoketest
/tmp/rotbyte-smoketest/bin/pip install --index-url https://test.pypi.org/simple/ rotbyte
/tmp/rotbyte-smoketest/bin/rotbyte --version
# rotbyte 1.3.0
/tmp/rotbyte-smoketest/bin/rotbyte --docs notify | head
```

### 7. Publish to the real PyPI

> **One-way door:** PyPI never lets a given version number be re-uploaded, even
> if you delete the release — `1.3.0` is burned forever once it's up. If
> anything looked off in Step 6, fix it and re-run `python3 -m build` before
> this step, not after.

```bash
twine upload dist/*
```

rotbyte is now live at `pypi.org/project/rotbyte/`, and the version/Python-version
badges already sitting in your `README.md` will start resolving.

### 8. Verify from a clean slate

```bash
python3 -m venv /tmp/rotbyte-verify
/tmp/rotbyte-verify/bin/pip install rotbyte
/tmp/rotbyte-verify/bin/rotbyte --version
```

Now go back to Step 3 and swap the account-wide token in `~/.pypirc` for a
project-scoped one.

### 9. Confirm the README badges picked it up

Two badges in `README.md` (lines 8-9) pull live data from PyPI via shields.io
— no config needed, they resolve automatically once the package exists:

- `pypi/v/rotbyte` — package version. Typically live within minutes of publish.
- `pypi/pyversions/rotbyte` — supported Python versions, read from the
  release's classifiers.

If the version badge resolves but the Python-versions one still shows
"package or version not found" shortly after publishing, it's almost
certainly a stale shields.io cache, not a real problem — shields.io renders
each badge once and caches the resulting image (`Cache-Control: max-age=21600`,
i.e. up to 6 hours) rather than querying PyPI live on every view. If your
first upload attempt failed (auth errors, etc.) and something — your browser,
GitHub rendering the README — requested the badge before the *successful*
attempt finished, shields cached a "not found" from that earlier moment and
will keep serving it until the cache entry ages out on its own. No action
needed; it self-corrects within 6 hours. To confirm immediately rather than
wait, force a live re-fetch that bypasses the cache:

```bash
curl -s "https://img.shields.io/pypi/pyversions/rotbyte.svg?cacheSeconds=1" | head -c 300
```

If that renders correctly, the stale image is the only issue and it'll clear
on its own.

Separately — and this part genuinely won't change until a future release —
compare what PyPI actually stored for your release against `pyproject.toml`:

```bash
curl -s https://pypi.org/pypi/rotbyte/json \
  | python3 -c "import json,sys; print('\n'.join(json.load(sys.stdin)['info']['classifiers']))"
```

Known gap as of the 1.3.0 release: PyPI's stored metadata is missing the
`Programming Language :: Python :: 3.13` and `:: 3.14` classifiers even
though both are declared in `pyproject.toml` — PyPI silently drops
classifiers it doesn't yet recognize server-side rather than failing the
upload. This isn't fixable by rebuilding or re-uploading (1.3.0's metadata is
immutable) and doesn't break anything (`requires-python = ">=3.9"` has no
upper bound, so `pip install` still works fine on 3.13/3.14) — it's purely
cosmetic on the badge, and will reflect correctly on your next version bump.

### 10. Close the loop with the rest of your release process

PyPI is only one of rotbyte's three distribution channels. Two things from your
own conventions still apply on every release, PyPI or not:

- Tag the commit (e.g. `v1.3.0`) and cut a GitHub release, since that tarball is
  what the Homebrew formula points at.
- Update the **separate Homebrew tap repo**'s formula — new `url` and `sha256`
  for the tag — independently of this PyPI upload; publishing here doesn't touch
  the tap.

## Optional — remove tokens from the equation

Once the manual flow above feels comfortable, PyPI's **Trusted Publishing** lets
GitHub Actions publish releases via short-lived OIDC credentials — no API token
stored anywhere, nothing to rotate or leak. Configure it on
`pypi.org/manage/project/rotbyte/settings/publishing/` by pointing it at your
GitHub repo, workflow filename, and environment. Worth doing after the first
manual release, not before — you want the manual mechanics to click first.

## Next release — quick reference

- [ ] Bump `VERSION` in all three places: `pyproject.toml`, `rotbyte.py`,
      `man/rotbyte.1`'s `.TH` line
- [ ] Run `./generate-man.sh` to re-stamp the man pages and re-sync bundled docs
- [ ] Run the test suite: `python3 -m pytest test_rotbyte.py`
- [ ] `rm -rf dist/ build/ *.egg-info && python3 -m build`
- [ ] `twine check dist/*`
- [ ] `twine upload dist/*` (project-scoped token from here on)
- [ ] Tag the release + GitHub release
- [ ] Bump `url`/`sha256` in the Homebrew tap repo

---

Reference: [packaging.python.org — packaging tutorial](https://packaging.python.org/en/latest/tutorials/packaging-projects/)
· [twine docs](https://twine.readthedocs.io/)
· [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
