# Driver IR Language

This is a reprensentation of my Driver IR.

TLDR,

- I have only three statements: `BuffDecl`, `BuffInit`, and `ApiCall` (I am thinking to a cast statement, not sure yet).
- All the `Variable` are allocated into `Buffers`, this allows me to handle arrays and scalars transparently (i.e., a pionter to a `Variable` also points to an `Buffer`)
- This schema allows to define `Buffer` of `PointerType`, even though it is not fully implemented yet. Only 2 leves are handled so far.

![alt text](./assets/grammar.jpg)