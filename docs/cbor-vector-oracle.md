# Independent CBOR Vector Check

The Appendix B Python encoder is independent from the Rust wire encoder. Its check
mode generates every normative frame and bare document in memory. It then compares
the bytes, in Appendix order, with the golden values in
`crates/carapace-wire/tests/vectors.rs`.

Install the exact Python dependencies and run the read-only check:

```sh
python -m pip install --requirement requirements-cbor-vectors.txt
python cbor_vectors.py --check
```

Check mode does not create or replace `appendix_b8_fragment.md`. It fails when the
vector count, order, or bytes differ. The normal generator mode keeps the existing
behavior for intentional appendix updates:

```sh
python cbor_vectors.py
```

CI runs check mode as a separate gate. The Rust golden-vector tests remain necessary:
they prove that the production encoder reproduces the same independently generated
bytes and that the production decoder rejects non-canonical input.
