I am trying to use SVF to build an analysis, but I am not sure what SVF's component better fits my needs.

First, I describe my problem along with a couple of examples to highlights the challenges.
Then, I discuss the approaches I considered. 

I would understand if my understanding is correct.
Specifically, what do I need, and what SVF's components I should use (and how).

TLDR; I don't know if I need a taint analysis, a source-sink, or just a SVF graph.

`Objective:` I am trying to come up with an analysis that tells me what fields of a structure are accessed and how (i.e., read or written).

Taking the Example 1 (below), I expect an output like this:
- `s->field_a`: is read and written
- `s->field_b`: is read and written
- `s->field_c`: is untouched

I believed I can achieve this output by traversing the SVFG graph. 
However, I am afraid this is not enough.

See the Example 2, the pointer `s->ss` is an alias of `as`. Following the SVGF graph, I understand that: 
- `s->ss->field_a`: is written
- `s->ss->field_b`: is read

However, I would understand that `as->field_a` and `as->field_b` are actually accessed, and not only the `s`'ones.

Following the SVFG, I can realize `s->ss` is an alias of `as`, but I am afraid this is not the correct way.

`My plan:` I guess I should come up with either a taint analysis or a source-sink analysis.  
Ideally, I would traverse the execution and infer:
1. `s` is used in a `GEP` instruction and infer the usage of a field `X`.
2. `X` ends up in a `STORE` as `dst` (for infer a write access) / `X` ends up in a `LOAD` (for infer a read access).

`Question1`: thus my plan makes sense?

`Question2`: how do implement this in SVF? In my mind I have three approaches, but I am not sure what to follow.

1) Implementation with taint analysis: How do I use SVF for this thing? I did not find any example in the repo (or if I miss, I kindly ask for clarification).

2) Implementation with source-sink analysis: I found the `LeakaChekger`, but this only checks if some variable is passing to a function argument, while I need something more "fine-grained", e.g, if a pointer is used as `src` in a `STORE` instruction. Is source-sink what I am looking for?

3) Only SVFG: I might use the graph to infer which fields are read/written, and then find the aliases. Finally, propagate the read/written to all the aliases. I understood how to make this approach, but I am afraid it will lead to too many false positives.


----

Example 1:
```
typedef struct my_struct {
    int field_a;
    int field_b;
    int field_c;
} my_struct;

void fun(my_struct* s) {
    int t;
    t = s->field_a;
    s->field_a = s->field_b;
    s->field_b = t;
}
```

Example 2:
```
typedef struct my_substruct {
    int field_a;
    int field_b;
} my_substruct;

typedef struct my_struct {
    my_substruct* ss;
} my_struct;

void fun(my_struct* s, my_substruct* as) {
    s->ss = as;
    s->ss->field_a = s->ss->field_b + 10;
}
```