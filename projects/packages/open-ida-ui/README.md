# @wae/open-ida-ui

Static Studio shell for OpenIDA, built on VMZ. It is the window opened by
`open-ida gui`; it holds no analysis logic and renders only what the connected
host reports.

The build emits `dist/static`, which the repository stages into
`projects/packages/open-ida/dist/gui`. When the shell runs without a connected
host it shows an empty state instead of sample data.

## Example

The app does not import this package. Run the Studio through the main package:

```bash
open-ida gui
```

The package is private and is not an installation target.
