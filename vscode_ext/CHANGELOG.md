# Change Log

All notable changes to the "phpwn" extension will be documented in this file.

Check [Keep a Changelog](http://keepachangelog.com/) for recommendations on how to structure this file.

## [0.1.0]

Initial public release.

- Fixed the Python virtual environment setup failing on Windows (it always ran `python3`, which typically isn't registered there).
- Fixed configuration/analysis breaking on workspace paths containing spaces.
- Fixed commands using a stale workspace path if the workspace folder changed after the extension activated.
- Fixed the Results and Variables panels potentially crashing instead of showing a clear message when `phpwn.config.json` or the report file is malformed.
- The bundled PHPwn version is now checked on every analysis run: upgrading the extension automatically picks up the new version on already-configured projects, no manual reset needed.
