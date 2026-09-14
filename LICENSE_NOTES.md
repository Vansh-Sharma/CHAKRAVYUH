# License Notes

CHAKRAVYUH is released under the **Apache License, Version 2.0** (the "License").
A copy of the full license text is in the [`LICENSE`](LICENSE) file in the repository root.

## Apache 2.0 Summary

You may:

- Use, copy, modify, and distribute this software for personal and commercial purposes.
- Sublicense and distribute modified versions under the same or a compatible license.
- Embed CHAKRAVYUH in closed-source products without disclosing your source code.

You must:

- Include a copy of the License and copyright notice in all copies or substantial portions.
- State significant changes made to the original software.
- Retain all original copyright, patent, trademark, and attribution notices.

The License does **not** grant patent rights from contributors to you.
See Section 3 of the License for full terms.

---

## Third-Party Dependencies

All direct and transitive dependencies declared in `Cargo.toml` and locked in
`Cargo.lock` are licensed under Apache-2.0, MIT, BSD-2-Clause, or BSD-3-Clause.
These are all permissive licenses compatible with Apache 2.0 distribution.

Run the following to regenerate a full license inventory:

```bash
cargo install cargo-license
cargo-license --json > third-party-licenses.json
```

---

## Optional Feature: Redis

Building with `--features redis` adds the [`redis`](https://crates.io/crates/redis) crate
(version 0.27) as a dependency. The `redis` crate is licensed under the
**BSD-3-Clause** license, which is compatible with Apache 2.0.

---

## MaxMind GeoLite2 Database

The Geo Fencer engine in the Shield Ring can use MaxMind's GeoLite2 database for
IP-based geolocation. The GeoLite2 database is **not** bundled with CHAKRAVYUH —
operators must download it separately from MaxMind.

The GeoLite2 database is licensed under the **Creative Commons Attribution-
ShareAlike 4.0 International (CC-BY-SA 4.0)** license and is subject to MaxMind's
separate [GeoLite2 EULA](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

This EULA is independent of and distinct from CHAKRAVYUH's Apache 2.0 license.
If you use the GeoLite2 database, you must comply with MaxMind's terms separately.

---

## Trademark

"CHAKRAVYUH" and the CHAKRAVYUH logo are trademarks of VINOMOID. Use of these
marks in derivative works or publications requires prior written permission.