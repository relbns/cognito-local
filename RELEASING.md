# Releasing

A release is a pushed `vX.Y.Z` tag that matches the `version` in `package.json`.

1. In a pull request to `main`, set the version and add its notes:
   - `npm version X.Y.Z --no-git-tag-version` updates `package.json` and `package-lock.json`.
   - Add a `## X.Y.Z` section at the top of `CHANGELOG.md`: it becomes the GitHub release notes.
2. After the merge, tag the merged commit and push the tag:

   ```bash
   git fetch origin
   git tag vX.Y.Z origin/main
   git push origin vX.Y.Z
   ```

The tag starts two workflows:

- `.github/workflows/release.yml` checks that the tag matches `package.json`, runs `npm ci`, the
  build and the tests, and stages the version on npm with provenance through npm trusted
  publishing (OIDC), so no npm token is stored in the repository. The trusted publisher may only
  stage: the version goes public when a maintainer approves it with 2FA, either on the package's
  page on npmjs.com or with `npm stage list` and `npm stage approve <stage-id>`. The GitHub release
  is created once the version is on npm; the job waits up to 2 hours and can be re-run after a
  later approval. A version that is already on npm is not staged again.
- `.github/workflows/docker.yml` pushes `ghcr.io/relbns/cognito-local` as `X.Y.Z`, `X.Y`, `X` and
  `latest`.

A pre-release version such as `1.1.0-rc.1` goes to the npm dist-tag `next`, becomes a GitHub
pre-release, and does not move the `latest` image.

## One-time setup

- `1.0.0` is published by hand from a clean checkout of the `v1.0.0` commit
  (`npm publish --access public`), because npm adds a trusted publisher only to a package that
  exists. Pushing the `v1.0.0` tag afterwards creates the GitHub release and the images.
- On npmjs.com, the package's trusted publisher is GitHub Actions with owner `relbns`, repository
  `cognito-local` and workflow `release.yml`, with no environment and with direct `npm publish`
  and `npm dist-tag` not allowed. Publishing access requires 2FA and disallows bypass tokens.
