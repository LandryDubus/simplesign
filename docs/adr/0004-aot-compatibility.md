# ADR 0004: AOT Compatibility (No Reflection, No Dynamic)

**Status:** Accepted (permanent)

**Context:**
.NET Native AOT (Ahead-of-Time compilation) requires that all code is statically analyzable. Reflection, `dynamic`, `Assembly.Load`, and runtime code generation are not compatible with AOT. Many .NET libraries silently use these features, making them incompatible with AOT publishing.

**Decision:**
SimpleSign maintains AOT compatibility as a first-class requirement:

- No `Assembly.Load`, `Activator.CreateInstance`, or `MethodInfo.Invoke`
- No `dynamic` keyword
- No runtime code generation (Reflection.Emit, Expression trees)
- All serialization uses AOT-compatible patterns
- The AOT smoke test (`SimpleSign.AotSmokeTest`) runs in CI to prevent regressions

**Consequences:**
- Full support for `dotnet publish -aot` and single-file deployment
- Zero runtime code generation means predictable startup time
- Some convenience patterns (DI auto-discovery, convention-based binding) require explicit registration
- Reduced flexibility in plugin/extensibility architecture
- Slightly more verbose code for otherwise reflective patterns

**Status:** This decision is permanent. AOT compatibility will not be compromised.
