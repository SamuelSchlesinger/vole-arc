## Summary

Describe the behavior and trust boundary changed by this pull request.

## Validation

- [ ] `scripts/check.sh full`
- [ ] Relevant positive, negative, and deterministic-vector tests
- [ ] Documentation and protocol paper synchronized with the implementation

## Cryptographic review

- [ ] Witness generation and circuit constraints agree
- [ ] Contexts, suite, version, limit, binding, and tag are transcript-bound
- [ ] Domain separation and wire-version consequences were reviewed
- [ ] Counter rollback, retry behavior, and atomic tag storage were reviewed
- [ ] Decoder bounds and canonical encodings were reviewed
- [ ] Secret lifetime, timing, allocation, and dependency behavior were reviewed
- [ ] Security claims do not exceed the evidence

If an item does not apply, explain why in the pull request description.
