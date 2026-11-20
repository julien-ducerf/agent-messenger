# Third-party dependency licenses

The project does not vendor these dependencies; package managers install them
separately from the pinned versions in `uv.lock`. Their upstream notices remain
applicable. Direct runtime dependencies:

- MCP Python SDK: MIT — <https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE>
- Starlette: BSD-3-Clause — <https://github.com/Kludex/starlette/blob/main/LICENSE.md>
- Uvicorn: BSD-3-Clause — <https://github.com/Kludex/uvicorn/blob/main/LICENSE.md>
- cryptography: Apache-2.0 or BSD-3-Clause — <https://github.com/pyca/cryptography>
- h11: MIT — <https://github.com/python-hyper/h11/blob/master/LICENSE.txt>
- PyJWT: MIT — <https://github.com/jpadilla/pyjwt/blob/master/LICENSE>

Development dependencies are also pinned in `uv.lock` and are installed only
for development. Recheck licenses when changing dependencies or distributing a
binary bundle. This list identifies direct dependencies, not every transitive
package.
