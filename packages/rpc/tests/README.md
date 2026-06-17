# Dev Note
Do NOT use `main` func when writing your test case writes over function names as it will create a conflict with other test cases and cause them to fail

Instead, create your own `foo` function in `basic.c` and use that instead
```c
void foo_comment(pool *p) {
    node *c = NULL;
    for (size_t i = 0; i < p->n; i++) {
        node *t = foo_make((int)i * 31);
        c = bar_link(t, c);
    }
    p->head = c;
}
```
