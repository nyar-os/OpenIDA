# @wae/open-ida-linux-arm64

Linux ARM64 native addon for `@wae/open-ida`. **Not a public import target.**

Installed automatically as an optional dependency of `@wae/open-ida` on a
matching host. The package contains one staged `.node` file.

## Example

Application code imports the main package; this artifact loads underneath it:

```ts
import { OpenIDA } from '@wae/open-ida';

const ida = new OpenIDA({ path: '/samples/app' });
console.log(ida.info().architecture);
ida.close();
```

The addon is not published yet. See the
[root README](../../../readme.md) for the product overview.
